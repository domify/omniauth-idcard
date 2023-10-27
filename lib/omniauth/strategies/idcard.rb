require 'omniauth-oauth'
require 'openssl'
require 'uri'

module OmniAuth
  module Strategies
    class Idcard < OmniAuth::Strategies::OAuth
      default_options.update(
        name: 'idcard',
        logger: nil,
        cert_variable: 'HTTP_X_SSL_CLIENT_S_CERT' # Name of the variable from Nginx
      )

      uid { @user_data['serialNumber'] }

      info do
        {
          'uid' => uid,
          'user_info' => {
            'personal_code' => @user_data['serialNumber'],
            'first_name' => @user_data['GN'],
            'last_name' => @user_data['SN'],
            'name' => "#{@user_data['GN']} #{@user_data['SN']}"
          }
        }
      end

      def pem
        @pem = @env[options.cert_variable]
        @pem = @env['HTTP_SSL_CLIENT_CERT'] if @pem.blank? # fall back to classic variable
        @pem
      end

      def request_phase
        if pem.blank?
          debug "Could not authenticate with ID-Card. Certificate is missing."
          return fail!(:client_certificate_missing)
        end

        debug "Start authentication with ID-Card. Got certificate from request #{pem}:"

        @user_data = parse_client_certificate(pem)
        @env['REQUEST_METHOD'] = 'GET'
        @env['omniauth.auth'] = info
        @env['PATH_INFO'] = "#{OmniAuth.config.path_prefix}/#{name}/callback"

        debug "ID-Card request was authenticated successfully. User data: #{info.inspect}"

        call_app!
      end

      def callback_phase
        fail!(:invalid_credentials)
      end

      def parse_client_certificate(data)
        data = URI.decode_www_form_component(data.to_s.delete("\t")) # Updated decoding method
        cert = OpenSSL::X509::Certificate.new(data)
        subject_dn = unescape(cert.subject.to_s).force_encoding('UTF-8')
        debug "Subject DN: #{subject_dn}"

        subject_dn.split('/').each_with_object(Hash.new) do |part, memo|
          item = part.split('=')
          memo[item.first.to_s] = item.last if item.last
        end
      end

      def unescape(value)
        value.gsub( /\\(?:([nevfbart\\])|0?x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))/) do
          if $3
            ["#$3".hex ].pack('U*')
          elsif $2
            [$2].pack( "H2" )
          else
            UNESCAPES[$1]
          end
        end
      end

      private

      def debug(message)
        options[:logger].debug("#{Time.now} #{message}") if options[:logger]
      end
    end
  end
end
