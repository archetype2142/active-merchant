module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PayuPolskaGateway < Gateway
      self.test_url = 'https://secure.snd.payu.com'
      self.live_url = 'https://secure.payu.com'

      self.supported_countries = ['PL']
      self.default_currency = 'PLN'
      self.money_format = :cents
      self.supported_cardtypes = %i[visa master]

      self.homepage_url = 'https://poland.payu.com/en/home/'
      self.display_name = 'PayU Polska'

      #
      # options = { :order_id       => order.id,
      #             :description    => "Some description",
      #             :referrer       => request.env['HTTP_REFERER'],
      #             :user_agent     => request.env['HTTP_USER_AGENT'],
      #             :ip             => request.remote_ip,
      #             :ext_order_id   => "123",
      #             :customer       => { 
      #               :first_name     => user.first_name,
      #               :last_name      => user.last_name,
      #               :email          => user.email,
      #               :phone          => user.phone,
      #               :language       => user.locale 
      #             }
      #             :products       => [{
      #               :name           => product.name
      #               :unit_price      => product.unit_price,
      #               :quantity       => product.quantity 
      #             }]
      #           }

      # notify_url is the webhook callback URL
      def initialize(options = {})
        requires!(options, :merchant_pos_id, :client_id, :client_secret, :notify_url)
        super
      end

      def purchase(money, options = {})
        post = {}
        add_invoice(post, money, options)
        add_customer_data(post, options)

        authorize(options)
        commit('api/v2_1/orders', post)
      end

      def app_token_from(response)
        options[:app_token] = response.params['access_token']
      end

      def app_token_request(options)
        {
          grant_type: 'client_credentials',
          client_id: @options[:client_id],
          client_secret: @options[:client_secret]
        }
      end

      def authorize(options = {})
        response = commit('pl/standard/user/oauth/authorize', app_token_request(options))
        app_token_from(response)
      end

      def capture(money, authorization, options = {})
        commit('capture', post)
      end

      def refund(money, authorization, options = {})
        commit('refund', post)
      end

      def void(authorization, options = {})
        commit('void', post)
      end

      def verify(credit_card, options = {})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def supports_scrubbing?
        false
      end

      def scrub(transcript)
        transcript
      end

      private

      def add_customer_data(post, options)
        post[:buyer] = {}
        post[:buyer][:email] = options&.dig(:email)
        post[:buyer][:phone] = options&.dig(:phone)
        post[:buyer][:firstName] = options[:customer]&.dig(:first_name)
        post[:buyer][:lastName] = options[:customer]&.dig(:last_name)
        post[:buyer][:language] = options[:customer]&.dig(:language)
      end

      def add_invoice(post, money, options)
        post[:totalAmount] = amount(money)
        post[:currencyCode] = (options[:currency] || currency(money))
        post[:description] = options[:description]
        post[:customerIp] = options[:ip]
        post[:merchantPosId] = @options[:merchant_pos_id]
        post[:extOrderId] = options&.dig(:ext_order_id)
        post[:products] = options[:products].map do |product|
          {
            name: product&.dig(:name),
            unitPrice: product&.dig(:unit_price),
            quantity: product&.dig(:quantity)
          }
        end
      end

      def parse(body)
        JSON.parse(body)
      end

      def response_builder(response)
        Response.new(
          success_from(response),
          message_from(response),
          response,
          authorization: authorization_from(response),
          avs_result: AVSResult.new(code: response['some_avs_response_key']),
          cvv_result: CVVResult.new(response['some_cvv_response_key']),
          test: test?,
          error_code: error_code_from(response)
        )
      end

      def headers(options)
        headers = {
          'Content-Type' => "application/json"
        }

        headers['Authorization'] = "Bearer #{options[:app_token]}" if options[:app_token]
        headers
      end

      def commit(action, parameters)
        url = (test? ? test_url : live_url)

        if action == 'pl/standard/user/oauth/authorize'
          post_url = "#{url}/#{action}?#{parameters.to_query}"
        else
          post_url = "#{url}/#{action}"
        end

        response = parse(ssl_post(post_url, parameters.to_json, headers(options)))

        response_builder(response)
      rescue ActiveMerchant::ResponseError => e
        raise unless e.response.code == "302"
        return response_builder(JSON.parse(e.response.body))
      end

      def success_from(response); end

      def message_from(response); end

      def authorization_from(response); end

      def error_code_from(response)
        unless success_from(response)
          # TODO: lookup error code for this response
        end
      end
    end
  end
end
