LitPHP/middleware-**ip-adress**
===============================

PSR-15 middleware for get client ip address from request

a complete rewrite of [akrabat/rka-ip-address-middleware](https://github.com/akrabat/rka-ip-address-middleware), 
using most of it's test cases

### Features

+ based on PSR-15
+ require PHP>=7.1 (for nullable typehint, and 7.0's lifecycle is in fact shorter than 5.6)
+ MUST provide `$trustedProxies` in order to inspect forwarding headers (security by default)
+ instead of use magic attribute name, use class name to attach the class instance to request

### Example

```php
<?php
use Lit\Middleware\IpAddress;

//bootstraping
$ipAddress = new IpAddress(['YOUR_TRUSTED_REVERSE_PROXY']);
ADD_MIDDLEWARE_TO_YOUR_APP($ipAddress, $app);

//in your business logic
$ip = IpAddress::fromRequest($request)->getIpAddress(); //string|null
```
