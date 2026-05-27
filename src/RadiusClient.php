<?php

namespace Mivo\Radius;

class RadiusClient
{
    private string $server;

    private string $secret;

    private int $port;

    private int $timeout;

    private int $identifier = 0;

    /**
     * Create a new UDP Radius Client
     *
     * @param  string  $server  IP Address or Hostname of the NAS/Radius Server
     * @param  string  $secret  Shared Secret
     * @param  int  $port  UDP Port (1812 for Auth, 1813 for Acct, 3799 for CoA/PoD)
     * @param  int  $timeout  Timeout in seconds
     */
    public function __construct(string $server, string $secret, int $port = 3799, int $timeout = 5)
    {
        $this->server = $server;
        $this->secret = $secret;
        $this->port = $port;
        $this->timeout = $timeout;
        $this->identifier = mt_rand(0, 255);
    }

    /**
     * Send a Packet of Disconnect (PoD) to the NAS.
     *
     * @param  string  $username  The PPPoE/Hotspot username to disconnect
     * @return bool True if Disconnect-ACK received, false if NAK or timeout
     */
    public function disconnectUser(string $username): bool
    {
        $packet = new RadiusPacket(RadiusPacket::DISCONNECT_REQUEST, $this->getNextIdentifier());

        // User-Name (Type 1)
        $packet->addAttribute(1, $username);

        // Add Message-Authenticator (Type 80)
        // Disconnect requests require Message-Authenticator for security (RFC 5176)
        // We append a 16-byte zero string first, calculate the HMAC, then replace it.
        $this->addMessageAuthenticator($packet);

        $response = $this->send($packet);

        if ($response && $response->getCode() === RadiusPacket::DISCONNECT_ACK) {
            return true;
        }

        return false;
    }

    /**
     * Adds the Message-Authenticator attribute (Type 80) to the packet
     * calculating the HMAC-MD5 of the entire packet.
     */
    private function addMessageAuthenticator(RadiusPacket $packet): void
    {
        // Add 16 empty bytes as a placeholder
        $emptyMac = str_repeat("\0", 16);
        $packet->addAttribute(80, $emptyMac);

        // Pack the packet with the empty mac
        $binaryPacket = $packet->pack();

        // Calculate HMAC-MD5 using the shared secret
        $hmac = hash_hmac('md5', $binaryPacket, $this->secret, true);

        // Replace the last attribute (which is our empty MAC) with the real HMAC
        $attributes = $packet->getAttributes();
        $lastIndex = count($attributes) - 1;

        $packet->updateAttribute($lastIndex, $hmac);
    }

    /**
     * Get next 8-bit identifier (0-255)
     */
    private function getNextIdentifier(): int
    {
        $this->identifier = ($this->identifier + 1) % 256;

        return $this->identifier;
    }

    /**
     * Sends the Radius packet over UDP and waits for the response.
     */
    public function send(RadiusPacket $packet): ?RadiusPacket
    {
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (! $socket) {
            throw new \RuntimeException('Unable to create UDP socket.');
        }

        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $this->timeout, 'usec' => 0]);
        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, ['sec' => $this->timeout, 'usec' => 0]);

        $data = $packet->pack();

        $bytesSent = @socket_sendto($socket, $data, strlen($data), 0, $this->server, $this->port);

        if ($bytesSent !== strlen($data)) {
            socket_close($socket);

            return null; // Failed to send
        }

        $responseBuffer = '';
        $fromIP = '';
        $fromPort = 0;

        $bytesReceived = @socket_recvfrom($socket, $responseBuffer, 4096, 0, $fromIP, $fromPort);
        socket_close($socket);

        if ($bytesReceived === false || $bytesReceived === 0) {
            return null; // Timeout or no response
        }

        try {
            return RadiusPacket::unpack($responseBuffer);
        } catch (\Exception $e) {
            return null;
        }
    }
}
