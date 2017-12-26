<?php

declare(strict_types=1);

namespace Lit\Middleware;

use Nimo\AbstractMiddleware;
use Nimo\Traits\MiddlewareTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IpAddress extends AbstractMiddleware
{
    use MiddlewareTrait;

    /**
     * @var array
     */
    protected $trustedProxies;
    /**
     * @var array
     */
    protected $headers;
    /**
     * @var string
     */
    protected $ipAddress;

    public function __construct(
        array $trustedProxies = [],
        array $headers = []
    ) {
        $this->trustedProxies = $trustedProxies;
        $this->headers = $headers;
    }

    /**
     * @return string
     */
    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public static function getIpAddressFromRequest(
        ServerRequestInterface $request,
        array $trustedProxies = [],
        array $headers = []
    ): ?string {
        $headers = $headers ?: [
            'Forwarded',
            'X-Forwarded-For',
            'X-Forwarded',
            'X-Cluster-Client-Ip',
            'Client-Ip',
        ];

        $params = $request->getServerParams();

        $remoteAddr = $params['REMOTE_ADDR'] ?? '';
        if (!self::isValidIpAddress($remoteAddr)) {
            return null;
        }

        if (empty($trustedProxies) || !in_array($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        foreach ($headers as $headerField) {
            if (!$request->hasHeader($headerField)) {
                continue;
            }
            $ip = self::getIpAddressFromHeaderField($request, $headerField);
            if ($ip) {
                return $ip;
            }
        }

        return $remoteAddr;
    }

    protected function main(): ResponseInterface
    {
        $this->attachToRequest();
        $this->ipAddress = static::getIpAddressFromRequest($this->request, $this->trustedProxies, $this->headers);

        return $this->delegate();
    }

    protected static function isValidIpAddress(string $ip): bool
    {
        return false !== filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6);
    }

    protected static function getIpAddressFromHeaderField(ServerRequestInterface $request, string $headerName): ?string
    {
        $headerValue = trim(explode(',', $request->getHeaderLine($headerName))[0]);

        if (ucfirst($headerName) == 'Forwarded') {
            foreach (explode(';', $headerValue) as $headerPart) {
                if (strtolower(substr($headerPart, 0, 4)) == 'for=') {
                    $for = explode(']', $headerPart);
                    $headerValue = trim(substr($for[0], 4), " \t\n\r\0\x0B\"[]");
                    break;
                }
            }
        }

        return static::isValidIpAddress($headerValue) ? $headerValue : null;
    }
}
