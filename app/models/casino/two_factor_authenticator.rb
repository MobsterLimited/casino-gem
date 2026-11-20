
class CASino::TwoFactorAuthenticator < ActiveRecord::Base
  belongs_to :user

  scope :active, -> { where(active: true) }

  def secret
    stored_secret = self[:secret]
    return stored_secret unless stored_secret && stored_secret.start_with?('v1:')

    self.class.secret_encryptor.decrypt_and_verify(stored_secret.delete_prefix('v1:'))
  end

  def secret=(value)
    self[:secret] = value.nil? ? nil : 'v1:' + self.class.secret_encryptor.encrypt_and_sign(value)
  end

  def self.secret_encryptor
    key_generator = Rails.application.key_generator
    encryption_key = key_generator.generate_key('casino two factor encryption v1', 32)
    signing_key = key_generator.generate_key('casino two factor signing v1', 32)
    ActiveSupport::MessageEncryptor.new(encryption_key, signing_key, digest: 'SHA256',
                                       serializer: ActiveSupport::MessageEncryptor::NullSerializer)
  end

  def self.cleanup
    self.delete_all(['(created_at < ?) AND active = ?', self.lifetime.ago, false])
  end

  def self.lifetime
    CASino.config.two_factor_authenticator[:lifetime_inactive].seconds
  end

  def expired?
    !self.active? && (Time.now - (self.created_at || Time.now)) > self.class.lifetime
  end
end
