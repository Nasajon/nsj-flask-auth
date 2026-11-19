<?php
require '/var/www/html/vendor/autoload.php';
require_once '/var/www/html/app/AppKernel.php';
final class ServiceAccountConsumerSmokeKernel extends AppKernel
{
    public function getCacheDir(): string { return '/tmp/service-account-consumers/cache'; }
    public function getLogDir(): string { return '/tmp/service-account-consumers/logs'; }
}
$kernel=new ServiceAccountConsumerSmokeKernel('prod',false);
$request=Symfony\Component\HttpFoundation\Request::createFromGlobals();
$response=$kernel->handle($request);$response->send();$kernel->terminate($request,$response);
