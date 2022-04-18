# frozen_string_literal: true

#                         **DEV-NOTE**
# This is a complete COPY of the mandrill-api gem's source.
# Due to security issue dealing with the JSON(CVE-2020-10663) gem and the fact
# that mandrill-api hasn't been updated in a very long time. We've decided to simply
# port this gem's (simple) source code over, so we can allow bundler the ability to update the
# JSON gem to version 2.4+ (mandrill-api limits the JSON gem version to 1.x)
#
# If by some miracle mandrill team actually updates their gem, we should convert over to it instead.
#

require 'rubygems'
require "excon"
require "json"
require "mandrill/errors"
require "mandrill/api"

module Mandrill
  class API
    attr_accessor :host, :path, :apikey, :debug, :session

    def initialize(apikey = nil, debug = false)
      @host = "https://mandrillapp.com"
      @path = "/api/1.0/"

      @session = Excon.new @host
      @debug = debug

      apikey ||= ENV["MANDRILL_APIKEY"] || read_configs

      raise Error.new("You must provide a Mandrill API key") unless apikey

      @apikey = apikey
    end

    def call(url, params)
      params[:key] = @apikey
      params       = JSON.generate(params)
      response     = @session.post(
        path:    "#{@path}#{url}.json",
        headers: { "Content-Type" => "application/json" },
        body:    params
      )

      cast_error(response.body) if response.status != 200
      JSON.parse(response.body)
    end

    def read_configs
      apikey = nil

      [File.expand_path("~/.mandrill.key"), "/etc/mandrill.key"].each do |path|
        next unless File.exist?(path)

        apikey = File.read(path)&.strip
        break if apikey.present?
      end

      apikey
    end

    def cast_error(body)
      error_map = {
        "ValidationError"            => ValidationError,
        "Invalid_Key"                => InvalidKeyError,
        "PaymentRequired"            => PaymentRequiredError,
        "Unknown_Subaccount"         => UnknownSubaccountError,
        "Unknown_Template"           => UnknownTemplateError,
        "ServiceUnavailable"         => ServiceUnavailableError,
        "Unknown_Message"            => UnknownMessageError,
        "Invalid_Tag_Name"           => InvalidTagNameError,
        "Invalid_Reject"             => InvalidRejectError,
        "Unknown_Sender"             => UnknownSenderError,
        "Unknown_Url"                => UnknownUrlError,
        "Unknown_TrackingDomain"     => UnknownTrackingDomainError,
        "Invalid_Template"           => InvalidTemplateError,
        "Unknown_Webhook"            => UnknownWebhookError,
        "Unknown_InboundDomain"      => UnknownInboundDomainError,
        "Unknown_InboundRoute"       => UnknownInboundRouteError,
        "Unknown_Export"             => UnknownExportError,
        "IP_ProvisionLimit"          => IPProvisionLimitError,
        "Unknown_Pool"               => UnknownPoolError,
        "NoSendingHistory"           => NoSendingHistoryError,
        "PoorReputation"             => PoorReputationError,
        "Unknown_IP"                 => UnknownIPError,
        "Invalid_EmptyDefaultPool"   => InvalidEmptyDefaultPoolError,
        "Invalid_DeleteDefaultPool"  => InvalidDeleteDefaultPoolError,
        "Invalid_DeleteNonEmptyPool" => InvalidDeleteNonEmptyPoolError,
        "Invalid_CustomDNS"          => InvalidCustomDNSError,
        "Invalid_CustomDNSPending"   => InvalidCustomDNSPendingError,
        "Metadata_FieldLimit"        => MetadataFieldLimitError,
        "Unknown_MetadataField"      => UnknownMetadataFieldError
      }

      begin
        error_info = JSON.parse(body)
        if (error_info["status"] != "error") || !(error_info["name"])
          raise Error.new("We received an unexpected error: #{body}")
        end

        if error_map.key?(error_info["name"])
          raise error_map[error_info["name"]].new(error_info["message"])
        else
          raise Error.new(error_info["message"])
        end
      rescue JSON::ParserError
        raise Error.new("We received an unexpected error: #{body}")
      end
    end

    def templates
      Templates.new(self)
    end

    def exports
      Exports.new(self)
    end

    def users
      Users.new(self)
    end

    def rejects
      Rejects.new(self)
    end

    def inbound
      Inbound.new(self)
    end

    def tags
      Tags.new(self)
    end

    def messages
      Messages.new(self)
    end

    def whitelists
      Whitelists.new(self)
    end

    def ips
      Ips.new(self)
    end

    def internal
      Internal.new(self)
    end

    def subaccounts
      Subaccounts.new(self)
    end

    def urls
      Urls.new(self)
    end

    def webhooks
      Webhooks.new(self)
    end

    def senders
      Senders.new(self)
    end

    def metadata
      Metadata.new(self)
    end
  end
end
