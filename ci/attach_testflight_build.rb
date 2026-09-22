#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "time"
require "uri"

# Attaches the just-uploaded build to a TestFlight beta group so testers can
# see it. Apple does NOT auto-attach green builds to any group: without this
# step a build can be VALID on the app while invisible to every tester
# (seen 2026-09-16: build 2 sat unattached for ~30 minutes after a green run).
#
# Env required:
#   BUNDLE_ID                     com.jahmedia.hermesdeck
#   BUILD_NUMBER                  the CFBundleVersion just uploaded
#   BETA_GROUP_NAME               e.g. Internal Testers
#   APP_STORE_CONNECT_KEY_ID      ASC team key id
#   APP_STORE_CONNECT_ISSUER_ID   ASC issuer id
#   APP_STORE_CONNECT_KEY_PATH    path to the .p8 key file
class TestFlightGroupAttacher
  API_BASE = "https://api.appstoreconnect.apple.com"
  BUILD_WAIT_MINUTES = 25   # Apple pre-processing after upload
  ATTACH_RETRY_MINUTES = 10 # attach can race pre-processing; retry
  POLL_SECONDS = 30

  class AttachError < StandardError; end

  def initialize(env: ENV)
    @env = env
    @jwt_token = nil
  end

  def run
    build_id = wait_for_build
    attach_with_retries(build_id)
    verify(build_id)
    puts "Build #{build_number} attached to beta group \"#{group_name}\" — visible to testers."
  end

  private

  def wait_for_build
    deadline = Time.now + BUILD_WAIT_MINUTES * 60
    loop do
      builds = fetch_paginated_json(
        "/v1/builds",
        "filter[app]" => app_id,
        "filter[version]" => build_number,
        "fields[builds]" => "version",
        "limit" => "10"
      )
      if (match = builds.find { |b| b.dig("attributes", "version") == build_number })
        puts "Build #{build_number} found on App Store Connect (id #{match.fetch('id')})"
        return match.fetch("id")
      end

      raise AttachError, "Build #{build_number} not found after #{BUILD_WAIT_MINUTES} minutes." if Time.now > deadline

      warn "Build #{build_number} not visible yet; retrying in #{POLL_SECONDS}s…"
      sleep POLL_SECONDS
    end
  end

  def attach_with_retries(build_id)
    deadline = Time.now + ATTACH_RETRY_MINUTES * 60
    attempt = 0
    loop do
      attempt += 1
      code, body = post_json(
        "/v1/betaGroups/#{group_id}/relationships/builds",
        "data" => [{ "type" => "builds", "id" => build_id }]
      )
      return if [201, 204].include?(code)

      raise AttachError, "Attach failed permanently: HTTP #{code}: #{body}" if Time.now > deadline

      warn "Attach attempt #{attempt} got HTTP #{code}; retrying in #{POLL_SECONDS}s…"
      sleep POLL_SECONDS
    end
  end

  # Apple forbids reading this relationship from the build side (403
  # GET_RELATED), but the group side reads fine — verify there.
  def verify(build_id)
    request = Net::HTTP::Get.new(URI.join(API_BASE, "/v1/betaGroups/#{group_id}/relationships/builds"))
    request["Authorization"] = "Bearer #{jwt_token}"
    request["Accept"] = "application/json"

    response = Net::HTTP.start(URI(API_BASE).hostname, URI(API_BASE).port, use_ssl: true) do |http|
      http.request(request)
    end
    unless response.is_a?(Net::HTTPSuccess)
      raise AttachError, "Verification read failed with HTTP #{response.code}."
    end

    ids = JSON.parse(response.body).dig("data")&.map { |item| item.fetch("id") } || []
    return if ids.include?(build_id)

    raise AttachError, "Verification failed: build #{build_id} not in group \"#{group_name}\"."
  end

  def group_id
    @group_id ||= begin
      # ASC rejects filter[name] on some endpoints/accounts
      # (PARAMETER_ERROR.ILLEGAL), so filter client-side instead.
      groups = fetch_paginated_json(
        "/v1/apps/#{app_id}/betaGroups",
        "limit" => "200"
      )
      group = groups.find { |g| g.dig("attributes", "name") == group_name }
      raise AttachError, "No beta group named \"#{group_name}\" found for app #{app_id}." unless group

      warn "Beta group \"#{group_name}\": #{group.fetch('id')}"
      group.fetch("id")
    end
  end

  def app_id
    @app_id ||= begin
      apps = fetch_paginated_json(
        "/v1/apps",
        "filter[bundleId]" => bundle_id,
        "fields[apps]" => "bundleId",
        "limit" => "10"
      )
      app = apps.find { |item| item.dig("attributes", "bundleId") == bundle_id }
      raise AttachError, "No App Store Connect app found for bundle ID #{bundle_id}." unless app

      app.fetch("id")
    end
  end

  def fetch_paginated_json(path, params)
    url = URI.join(API_BASE, path)
    url.query = URI.encode_www_form(params)
    items = []

    loop do
      response = get_json(url)
      data = response.fetch("data")
      raise AttachError, "Expected App Store Connect data array from #{url}." unless data.is_a?(Array)

      items.concat(data)
      next_url = response.dig("links", "next")
      break if next_url.to_s.empty?

      url = URI(next_url)
    end

    items
  end

  def get_json(url)
    request = Net::HTTP::Get.new(url)
    request["Authorization"] = "Bearer #{jwt_token}"
    request["Accept"] = "application/json"

    response = Net::HTTP.start(url.hostname, url.port, use_ssl: url.scheme == "https") do |http|
      http.request(request)
    end

    unless response.is_a?(Net::HTTPSuccess)
      raise AttachError, "App Store Connect request failed with HTTP #{response.code}: #{response.body}"
    end

    JSON.parse(response.body)
  rescue JSON::ParserError => e
    raise AttachError, "App Store Connect returned invalid JSON: #{e.message}"
  end

  # Returns [status_code, parsed_body_or_raw]
  def post_json(path, payload)
    url = URI.join(API_BASE, path)
    request = Net::HTTP::Post.new(url)
    request["Authorization"] = "Bearer #{jwt_token}"
    request["Content-Type"] = "application/json"
    request["Accept"] = "application/json"
    request.body = JSON.generate(payload)

    response = Net::HTTP.start(url.hostname, url.port, use_ssl: url.scheme == "https") do |http|
      http.request(request)
    end
    [response.code.to_i, response.body.to_s[0, 300]]
  end

  def jwt_token
    @jwt_token ||= begin
      issued_at = Time.now.to_i - 60
      header = {
        alg: "ES256",
        kid: required_env("APP_STORE_CONNECT_KEY_ID"),
        typ: "JWT"
      }
      payload = {
        iss: required_env("APP_STORE_CONNECT_ISSUER_ID"),
        iat: issued_at,
        exp: issued_at + (20 * 60),
        aud: "appstoreconnect-v1"
      }

      signing_input = [base64url(header.to_json), base64url(payload.to_json)].join(".")
      signature = base64url(es256_signature(signing_input))
      "#{signing_input}.#{signature}"
    end
  end

  def es256_signature(signing_input)
    key = OpenSSL::PKey.read(File.read(required_env("APP_STORE_CONNECT_KEY_PATH")))
    der_signature = key.sign(OpenSSL::Digest::SHA256.new, signing_input)
    sequence = OpenSSL::ASN1.decode(der_signature)

    r = sequence.value[0].value.to_i
    s = sequence.value[1].value.to_i
    hex_signature = [r.to_s(16).rjust(64, "0"), s.to_s(16).rjust(64, "0")].join
    [hex_signature].pack("H*")
  end

  def base64url(value)
    Base64.strict_encode64(value).tr("+/", "-_").delete("=")
  end

  def bundle_id
    required_env("BUNDLE_ID")
  end

  def build_number
    required_env("BUILD_NUMBER")
  end

  def group_name
    required_env("BETA_GROUP_NAME")
  end

  def required_env(name)
    value = @env[name].to_s
    raise AttachError, "Missing required environment variable: #{name}" if value.empty?

    value
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    puts TestFlightGroupAttacher.new.run
  rescue TestFlightGroupAttacher::AttachError => e
    warn e.message
    exit 1
  end
end
