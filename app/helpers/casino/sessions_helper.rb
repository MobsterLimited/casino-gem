require 'addressable/uri'

module CASino::SessionsHelper
  include CASino::TicketGrantingTicketProcessor
  include CASino::ServiceTicketProcessor

  def current_ticket_granting_ticket?(ticket_granting_ticket)
    ticket_granting_ticket.ticket == cookies[:tgt]
  end

  def current_ticket_granting_ticket
    return nil unless cookies[:tgt]
    return @current_ticket_granting_ticket unless @current_ticket_granting_ticket.nil?
    find_valid_ticket_granting_ticket(cookies[:tgt], request.user_agent).tap do |tgt|
      cookies.delete :tgt if tgt.nil?
      @current_ticket_granting_ticket = tgt
    end
  end

  def current_user
    tgt = current_ticket_granting_ticket
    return nil if tgt.nil?
    tgt.user
  end

  def ensure_signed_in
    redirect_to login_path unless signed_in?
  end

  def signed_in?
    !current_ticket_granting_ticket.nil?
  end

  def sign_in(authentication_result, options = {})
    tgt = acquire_ticket_granting_ticket(authentication_result, request.user_agent, request.remote_ip, options)
    reset_session
    cookies.delete :tgt

    if tgt.awaiting_two_factor_authentication?
      session[:pending_tgt_id] = tgt.id
      session[:pending_service] = params[:service]
      session[:pending_credentials_supplied] = !!options[:credentials_supplied]
    else
      create_login_attempt(tgt.user, true)
      set_tgt_cookie(tgt)
    end

    handle_signed_in(tgt, options)
  end

  def set_tgt_cookie(tgt)
    cookies[:tgt] = { value: tgt.ticket, httponly: true, secure: request.ssl? || Rails.env.production? }.tap do |cookie|
      if tgt.long_term?
        cookie[:expires] = CASino.config.ticket_granting_ticket[:lifetime_long_term].seconds.from_now
      end
    end
  end

  def sign_out
    remove_ticket_granting_ticket(cookies[:tgt], request.user_agent)
    cookies.delete :tgt
  end

  def log_failed_login(username)
    CASino::User.where(username: username).each do |user|
      create_login_attempt(user, false)
    end
  end

  def create_login_attempt(user, successful)
    user.login_attempts.create! successful: successful,
                                user_ip: request.ip,
                                user_agent: request.user_agent
  end

  private

  def load_pending_two_factor_ticket
    pending = CASino::TicketGrantingTicket.where(id: session[:pending_tgt_id], awaiting_two_factor_authentication: true).first
    @ticket_granting_ticket = find_valid_ticket_granting_ticket(pending.ticket, request.user_agent, ignore_two_factor: true) if pending
    redirect_to login_path if @ticket_granting_ticket.nil?
  end

  def complete_two_factor_sign_in(ticket)
    service = session[:pending_service]
    credentials_supplied = session[:pending_credentials_supplied]
    create_login_attempt(ticket.user, true)
    reset_session
    params[:service] = service
    set_tgt_cookie(ticket)
    handle_signed_in(ticket, credentials_supplied: credentials_supplied)
  end

  def handle_signed_in(tgt, options = {})
    if tgt.awaiting_two_factor_authentication?
      @ticket_granting_ticket = tgt
      if tgt.user.active_two_factor_authenticator
        render 'casino/sessions/validate_otp'
      else
        redirect_to two_factor_enrollment_path
      end
    else
      if params[:service].present?
        begin
          handle_signed_in_with_service(tgt, options)
          return
        rescue Addressable::URI::InvalidURIError => e
          Rails.logger.warn "Service #{params[:service]} not valid: #{e}"
        end
      end
      redirect_to sessions_path, status: :see_other
    end
  end

  def handle_signed_in_with_service(tgt, options)
    if !service_allowed?(params[:service])
      @service = params[:service]
      render 'casino/sessions/service_not_allowed', status: 403
    else
      url = acquire_service_ticket(tgt, params[:service], options).service_with_ticket_url
      redirect_to url, status: :see_other
    end
  end
end
