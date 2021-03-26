from OpenSSL import crypto

CHAT_HELLO = 'CHAT_HELLO'
CHAT_REPLY = 'CHAT_REPLY'
CHAT_STARTTLS = 'CHAT_STARTTLS'
CHAT_STARTTLS_ACK = 'CHAT_STARTTLS_ACK'
CHAT_STARTTLS_NOT_SUPPORTED = 'CHAT_STARTTLS_NOT_SUPPORTED'
CHAT_INVALID_HANDSHAKE = 'CHAT_INVALID_HANDSHAKE'
CHAT_INVALID_CERTIFICATE = 'CHAT_INVALID_CERTIFICATE'
CHAT_MESSAGE = 'CHAT_MESSAGE'
CHAT_END = 'CHAT_END'

HANDSHAKE_FAILED = 'HANDSHAKE_ABORT'
HANDSHAKE_SUCESS_TLS = 'HANDSHAKE_SUCESS_TLS'
HANDSHAKE_SUCESS_NO_TLS = 'HANDSHAKE_SUCESS_NO_TLS'


def fragment(message, message_num):
  messsage_size = 8
  split = [message[i:i+messsage_size] for i in range(0, len(message), messsage_size)]
  prefix = 'CHAT_MESSAGE,' + format(message_num, '04d') + ',' + format(len(split), '04d') + ','
  fragment_numbers = [i for i in range(1, len(split)+1, 1)]
  split_message = [(prefix + format(y, '04d') + ',' + z).encode('UTF-8') for y,z in zip(fragment_numbers,split)]
  return split_message
  
def parse(split_message):
  messages = [split_message[i].decode('UTF-8')[28:] for i in range(len(split_message))]
  message = ''.join(messages)
  return message
  
def get_message_details(message):
  return int(message[13:17]), int(message[18:22]), int(message[23:27])
  
def cert_checker(certificate, trusted_certs):
  try:
    cert_store = crypto.X509Store()
    for cert in trusted_certs:
      cert_store.add_cert(cert)

    cert_context = crypto.X509StoreContext(cert_store, certificate)
    store_ctx.verify_certificate()
    return True
  except Exception as exc:
    print(exc)
    return False
