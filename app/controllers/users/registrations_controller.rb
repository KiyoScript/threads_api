# frozen_string_literal: true

class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  before_action :skip_session_cookies
  before_action :configure_sign_up_params, only: [ :create ]

  protected

  def configure_sign_up_params
    devise_parameter_sanitizer.permit(:sign_up, keys: [ :username, :email, :password, :password_confirmation, :remember_me ])
  end

  def respond_with(resource, options = {})
    if resource.persisted?
      render json: { status: { code: 200, message: "Sign up successfully", user: resource  } }, status: :ok
    else
      render json: { status: { code: 422,  message: "User could not be created", errors: resource.errors.full_messages } }, status: :unprocessable_entity
    end
  end

  def skip_session_cookies
    request.session_options[:skip] = true
  end
end
