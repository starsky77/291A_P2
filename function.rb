# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  # response(body: event, status: 200)

  http_method = event["httpMethod"]
  path = event["path"]
  headers = (event['headers'] || {}).transform_keys(&:downcase)

  if path == '/auth/token'
    if http_method == 'POST'
      post_auth_token(event, headers)
    else
      response(status: 405)
    end
  elsif path == '/'
    if http_method == 'GET'
      get_root(event, headers)
    else
      response(status: 405)
    end
  else
    response(status: 404)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    headers: {'Content-Type' => 'application/json' },
    statusCode: status
  }
end

def post_auth_token(event, headers)
  if headers['content-type'].nil? || headers['content-type'].strip.empty?
    return response(status: 415)
  end

  content_type = headers['content-type'].split(';').first.strip
  if content_type != 'application/json'
    return response(status: 415)
  end

  body = event['body']
  begin
    data = JSON.parse(body.to_s)
  rescue JSON::ParserError, TypeError
    return response(status: 422)
  end

  cotent = {
    'data' => data,
    'exp' => Time.now.to_i + 5,
    'nbf' => Time.now.to_i + 2
  }

  token = JWT.encode(cotent, ENV['JWT_SECRET'], 'HS256')
  response(body: { 'token' => token }, status: 201)

end

def get_root(event, headers)
  if not headers['authorization']&.start_with?('Bearer ')
    return response(status: 403)
  end

  token =  headers['authorization'].split(' ').last
  begin
    decoded_token = JWT.decode(token, ENV['JWT_SECRET'], true, algorithm: 'HS256')[0]
    data = decoded_token['data']
    response(body: data, status: 200)
  rescue JWT::ExpiredSignature, JWT::ImmatureSignature
    response(status: 401)
  rescue JWT::DecodeError
    response(status: 403)
  end

end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
