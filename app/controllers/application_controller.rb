class ApplicationController < ActionController::API
  private

  def authenticate_user!
    @current_actor = warden.authenticate(scope: :user)

    if !current_actor
      render json: { error: I18n.t("devise.failure.unauthenticated") }, status: :unauthorized
    end
  end

  def current_actor
    @current_actor
  end
end
