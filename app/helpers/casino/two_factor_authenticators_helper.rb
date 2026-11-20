require 'rqrcode'
require 'rqrcode_png'

module CASino::TwoFactorAuthenticatorsHelper
  def otp_auth_url(two_factor_authenticator)
    "otpauth://totp/#{u CASino.config.frontend[:sso_issuer] + ': ' + two_factor_authenticator.user.username}?secret=#{two_factor_authenticator.secret}&issuer=#{u CASino.config.frontend[:sso_issuer]}"
  end

  def otp_qr_code_data_url(two_factor_authenticator)
    auth_url = otp_auth_url(two_factor_authenticator)
    RQRCode::QRCode.new(auth_url, level: :l).as_png(size: 250).to_data_url
  end
end
