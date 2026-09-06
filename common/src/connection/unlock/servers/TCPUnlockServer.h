#ifndef PCBU_DESKTOP_TCPUNLOCKSERVER_H
#define PCBU_DESKTOP_TCPUNLOCKSERVER_H

#include "connection/unlock/BaseUnlockConnection.h"

class TCPUnlockServer : public BaseUnlockConnection {
public:
  TCPUnlockServer();

  bool IsServer() override;
  bool Start() override;
  void Stop() override;

private:
  void AcceptThread();
  void ClientThread(SOCKET clientSocket);

  SOCKET m_ServerSocket;
  std::atomic<int> m_NumConnections{};

  // Only one unlock exchange may be in flight at a time.
  //
  // Every accepted socket used to get its own PerformAuthFlow, and each of
  // those sends its own encrypted request - so a phone that opened two
  // connections was asked to approve twice. Phones do open more than one:
  // the UDP beacon repeats, and a client may dial again before the first
  // attempt completes.
  std::atomic<bool> m_AuthInProgress{};
};

#endif // PCBU_DESKTOP_TCPUNLOCKSERVER_H
