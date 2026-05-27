![Mivo Radius Core](https://raw.githubusercontent.com/mivodev/.github/main/profile/assets/img/logo-banner.png)

# Mivo Radius Core

A pure PHP RADIUS protocol client for Mivo Enterprise.

This package provides a framework-agnostic implementation to send RADIUS packets (UDP) such as Access-Request, Accounting-Request, Disconnect-Request (PoD), and CoA (Change of Authorization) to a RADIUS Server or a NAS (e.g. Mikrotik RouterOS).

## Features
- Pure UDP Socket Client (no PDO / database connections).
- Supports standard RADIUS Authentication and Accounting (RFC 2865, RFC 2866).
- Supports Dynamic Authorization / CoA / PoD (RFC 5176).

## Requirements
- PHP 8.2+
- `ext-sockets` enabled

## Usage

```php
use Mivo\Radius\RadiusClient;

$client = new RadiusClient('192.168.1.1', 'secret', 3799); // Port 3799 for CoA/PoD
$response = $client->disconnectUser('john_doe');

if ($response) {
    echo "User disconnected successfully!";
}
```