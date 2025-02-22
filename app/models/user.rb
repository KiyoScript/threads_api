class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  #
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: self


  validates :username, presence: true, uniqueness: { case_sensitive: false }

  attr_writer :email_or_username

  def jwt_payload
    super
  end

  def email_or_username
    @email_or_username || self.username || self.email
  end

  def self.find_first_by_auth_conditions(warden_conditions)
    conditions = warden_conditions.dup
    if (email_or_username = conditions.delete(:email_or_username))
      where(conditions).where([ "lower(username) = :value OR lower(email) = :value", { value: email_or_username.downcase } ]).first
    else
      if conditions[:username].nil?
        where(conditions).first
      else
        where(username: conditions[:username]).first
      end
    end
  end
end
