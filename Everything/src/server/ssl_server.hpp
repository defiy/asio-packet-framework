#ifndef SSL_SERVER_HPP
#define SSL_SERVER_HPP

#include <unordered_set>
#include "ssl_session.hpp"

class SSLServer
{
public:
	SSLServer(asio::io_context& io_context, unsigned short port);

	void Multicast(std::shared_ptr<IPacket> pPacket, SSLSession* pIgnore = NULL);

	void RemoveSession(std::shared_ptr<SSLSession> pSession);

	virtual bool VerifyCertificate(SSLSession* pSession, bool preverified, asio::ssl::verify_context& ctx);

	virtual void OnConnect(SSLSession* pSession) = 0;
	virtual void OnHandshake(SSLSession* pSession) = 0;
	virtual void OnError(SSLSession* pSession, std::error_code errc) = 0;

	virtual bool OnReceive(SSLSession* pSession, IPacket*pPacket) = 0;	// Called before the packet is processed
													// return true to process the packet

private:
	void R_Accept();

private:
	asio::ip::tcp::acceptor m_Acceptor;
	asio::ssl::context m_Context;
	UInt16 m_nPort;

	std::unordered_set<std::shared_ptr<SSLSession>> m_Sessions;

private:
	const char m_szServerCertificate[1308] = R"(
-----BEGIN CERTIFICATE-----
MIICrjCCAZYCFCQ3n41sg6Tat+jX43SVKoxLz+J4MA0GCSqGSIb3DQEBCwUAMBMx
ETAPBgNVBAMMCE15Um9vdENBMB4XDTI0MDkyNDA0MjYzMFoXDTI1MDkyNDA0MjYz
MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAtN/Mp/6q1DhKvajP+YlK0s15FquOEeJ4ew7Xs0Qov8+4yRmfAgZ5
Y4ituNncXujT8pvD17ZuncGxSbhmwqpBicAyWc+RNAWaDm9OLwPh0t+ih9heHBhS
sAahNJWAei8BD2/7qQqw3PEjLyqJOCc2q0X1KwVTG5NlQSJetGwsOVne+DjYpBui
UbySqCQE4/BXZMo0RztU3fSfl29u9+2UuVJyLqwzk+fVkklcTEaiaenri7RcfMpY
zeGnVnZM18QgJsCWrbxZAgtNMU0PLkWjezB6hiSsLnmMuuAUTjreAhr/eyby40GQ
erZk6DlhAHicCI5J/OKxo6jXkP6yZbxHfwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQByvU00lNCD+mylFW0NUrneqOc2SHyq0YBjCm07D/Jl/B/7MBy1ubS+/xVBeVy+
a8qAbb352pTmAoJxpzCzdyUQaxmXNW2nWFjXt7OS0JO97FRPP/iqjAZosTcZyv/v
+Wt/0YM4cNRVMmC73ZSC7mdR0Ubxh3do79laAUDscWz9EwFLU9Qx+aRDgBYJoi9M
DUzUwM909a1AVXN2gnWIcJuqxPRSbwhOkxB6i8qjrBcWZWGXyj6XJIBnD7nILP04
ZGVIzgj/fhdtjcJvvPnarwg+QBO+FXj4FJJTbODkf6d2SB4oDF0HqxwiwT6DK7yo
SupRibEpwGAcafxzIQbZROzP
-----END CERTIFICATE-----
)";
	const char m_szServerPrivateKey[1706] = R"(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC038yn/qrUOEq9
qM/5iUrSzXkWq44R4nh7DtezRCi/z7jJGZ8CBnljiK242dxe6NPym8PXtm6dwbFJ
uGbCqkGJwDJZz5E0BZoOb04vA+HS36KH2F4cGFKwBqE0lYB6LwEPb/upCrDc8SMv
Kok4JzarRfUrBVMbk2VBIl60bCw5Wd74ONikG6JRvJKoJATj8FdkyjRHO1Td9J+X
b2737ZS5UnIurDOT59WSSVxMRqJp6euLtFx8yljN4adWdkzXxCAmwJatvFkCC00x
TQ8uRaN7MHqGJKwueYy64BROOt4CGv97JvLjQZB6tmToOWEAeJwIjkn84rGjqNeQ
/rJlvEd/AgMBAAECggEAKEEUoaDOcRu0GqCq5JzXD7JWDCMTI8zUxoJnpAh7zzCS
LgNrPX6mXm4JR7YI0wCbRwe+ntAFr0tvwvnsuM8+dcNWEWHeLYc/oY3JBzKkfBN0
bypKy5LoOC/JidPp+4dhg4eHKThtY0axb2pWjq4/fv+7UB9Hvz/fDY9yJ1JZx0tm
wo6ZM5hk9HRlMa5mDYo4/9/HRVrb7eWG+7I53899ntBXGiy34Flf0y7TK9Amgd7I
1eMdaDG6X4FGOgAxrsT6O1Ye/V6sTcy8omK71jT+sdmXr2m6mmaYrZ1CE6R1cEHD
Xbjb9jlzlumoxQ+Vz0r7caWFUAeZm8JOGIjEoj4boQKBgQDcdYVaHdm5EiWezPpD
++gCfuHVWocO5k6ksbjVLmgefv3x1Ix7uz6IQVA/4Q8jd54LVkBC3cATq44EywjN
oCzEaZ+AF4erZxE+D1Y77OAROoc6lYjcMCWkD+x3v84WXvGF0HA432IN3iNAsovl
qCNaENlKGL0pL5AmTw/xUtTPnwKBgQDSCJZ8TP5RmISSxsQ0Rk556bGo4FP2Vvao
kTdA1+qETsdKc1lLqBdoz1wvG+LmYw1RagNMj0AA2p3iHKtUCmkQ1xu6r7Jc14DH
NmfIrn3/BebfgsfQcpGr/OkIhvk+lw58xhTn29AaZGMyIhDzDvP/6xsE+LW+dCaP
j6di2PP8IQKBgCMLg4FJ0Xx8CALwbrAz8TPEW74AwAt8TPAdWFZ7JA4E/fVdZl+c
6lnamBkve6qVr0f6FAkNGyWFVfQpGmMlnTgz2ikQlH6IydLluT2ZcB0NAsYrUzA9
bx5fcaWvleE0goxVECHaUMoHj+8O8vI1AjmlCAWhXSCY8P9F/jDMjAvdAoGBALAm
K6+MEy7zrxw6P4tn+6Ebcbiki0ZqoOu2/pQPgcv9Ff9GxnlBPIDWiAWqaZ23LRA+
zQ2EhrUwpIFicf5FzOAmyEbF290pkAODiX8xeNJNbNe/oz0bGTkZH4fbS2ZG4gub
RSU/oUTBNMBy+awfulvEHiEJRcO5Pi3g2Q15zwaBAoGAbgODKUoUwu1iNU8F8a3U
GyJmfm2R0c/mErmNEO1LbehRCLnKb5gvcsSw3sMqwA42W8IH8anT/c1YSef6SZCM
OdQl0IUkAXtfs6vVzBcvhLVKYQQNwemZPxzWMqwMwVtz/OUtxq9TOslAOHdQsfF0
WvkAvXULt3VgKWuS7AtcNqw=
-----END PRIVATE KEY-----
)";
};

#endif // !SSL_SERVER_HPP
