<?php

namespace Mivo\Radius;

class RadiusPacket
{
    public const ACCESS_REQUEST = 1;

    public const ACCESS_ACCEPT = 2;

    public const ACCESS_REJECT = 3;

    public const ACCOUNTING_REQUEST = 4;

    public const ACCOUNTING_RESPONSE = 5;

    public const DISCONNECT_REQUEST = 40;

    public const DISCONNECT_ACK = 41;

    public const DISCONNECT_NAK = 42;

    public const COA_REQUEST = 43;

    public const COA_ACK = 44;

    public const COA_NAK = 45;

    private int $code;

    private int $identifier;

    private string $authenticator;

    private array $attributes = [];

    public function __construct(int $code, int $identifier, string $authenticator = '')
    {
        $this->code = $code;
        $this->identifier = $identifier;

        if (empty($authenticator)) {
            // Generate random 16-byte authenticator
            $this->authenticator = random_bytes(16);
        } else {
            $this->authenticator = $authenticator;
        }
    }

    public function getCode(): int
    {
        return $this->code;
    }

    public function getIdentifier(): int
    {
        return $this->identifier;
    }

    public function getAuthenticator(): string
    {
        return $this->authenticator;
    }

    /**
     * Set the Request Authenticator (16 bytes)
     */
    public function setAuthenticator(string $authenticator): void
    {
        if (strlen($authenticator) !== 16) {
            throw new \InvalidArgumentException('Authenticator must be exactly 16 bytes.');
        }
        $this->authenticator = $authenticator;
    }

    /**
     * Add an attribute to the packet.
     *
     * @param  int  $type  Attribute ID (e.g., 1 for User-Name)
     * @param  string  $value  The raw byte string of the value
     */
    public function addAttribute(int $type, string $value): void
    {
        $this->attributes[] = [
            'type' => $type,
            'value' => $value,
        ];
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Update an existing attribute by index.
     */
    public function updateAttribute(int $index, string $newValue): void
    {
        if (isset($this->attributes[$index])) {
            $this->attributes[$index]['value'] = $newValue;
        } else {
            throw new \OutOfBoundsException("Attribute index {$index} does not exist.");
        }
    }

    /**
     * Pack the packet into a binary string for UDP transmission.
     */
    public function pack(): string
    {
        $packedAttributes = '';
        foreach ($this->attributes as $attr) {
            $type = $attr['type'];
            $value = $attr['value'];
            $length = strlen($value) + 2; // +2 for Type and Length fields

            // Limit attribute length to max 255
            if ($length > 255) {
                throw new \LengthException("Attribute type {$type} exceeds maximum length of 255 bytes.");
            }

            // Pack: 1 byte Type, 1 byte Length, N bytes Value
            $packedAttributes .= pack('CC', $type, $length).$value;
        }

        $totalLength = 20 + strlen($packedAttributes); // 20 bytes for the Radius Header

        // Radius Header:
        // 1 byte Code
        // 1 byte Identifier
        // 2 bytes Length
        // 16 bytes Authenticator
        $header = pack('CCn', $this->code, $this->identifier, $totalLength).$this->authenticator;

        return $header.$packedAttributes;
    }

    /**
     * Unpack a binary string from UDP into a RadiusPacket object.
     */
    public static function unpack(string $data): self
    {
        if (strlen($data) < 20) {
            throw new \UnexpectedValueException('Invalid Radius packet length.');
        }

        $header = unpack('Ccode/Cidentifier/nlength', substr($data, 0, 4));
        $authenticator = substr($data, 4, 16);

        $packet = new self($header['code'], $header['identifier'], $authenticator);

        $offset = 20;
        $totalLength = $header['length'];

        // Ensure total length matches data received
        if (strlen($data) < $totalLength) {
            throw new \UnexpectedValueException('Incomplete Radius packet.');
        }

        while ($offset < $totalLength) {
            $attrHeader = unpack('Ctype/Clength', substr($data, $offset, 2));
            $attrType = $attrHeader['type'];
            $attrLength = $attrHeader['length'];

            if ($attrLength < 2) {
                throw new \UnexpectedValueException('Invalid attribute length.');
            }

            $attrValue = substr($data, $offset + 2, $attrLength - 2);
            $packet->addAttribute($attrType, $attrValue);

            $offset += $attrLength;
        }

        return $packet;
    }
}
