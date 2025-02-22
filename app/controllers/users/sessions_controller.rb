# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  respond_to :json

  before_action :configure_sign_in_params, only: [ :create ]
  before_action :skip_session_cookies

  protected

  def respond_with(resource, options = {})
    @token = request.env["warden-jwt_auth.token"]
    headers["Authorization"] = @token

    if resource.persisted?
      render json: { status: { code: 200, message: "Signed in successfully", data: resource } }, status: :ok
    else
      render json: { status: { code: 401, message: "Invalid credentials" } }, status: :unauthorized
    end
  end

  def respond_to_on_destroy
    jwt_payload = JWT.decode(request.headers["Authorization"].split(" ")[1], Rails.application.credentials.devise_jwt_secret_key!).first

    current_user = User.find(jwt_payload["sub"])
    if current_user
      render json: { status: { status: 200, message: "Signed out successfully" } }, status: :ok
    else
      render json: { status: { status: 401, message: "Account not found" } }, status: :unauthorized
    end
  end

  def configure_sign_in_params
    devise_parameter_sanitizer.permit(:sign_in, keys: [ :email_or_username, :password ])
  end

  def skip_session_cookies
    request.session_options[:skip] = true
  end
end
