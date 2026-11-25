<?php

declare(strict_types=1);

namespace McSec;

/**
 * «بررسی رایگان DNS»: a page without a login (p=check) where anyone types a domain and sees what its PUBLIC DNS
 * records say about e-mail spoofing and certificate issuance: name servers, addresses, MX, SPF, DMARC, CAA.
 *
 * It reads DNS records only. No request of any kind goes to the server of the domain: no HTTP, no TLS, no ports.
 * That is why it needs no proof of ownership (rule 1 is about scanning a target; a public DNS record is published
 * for everyone to read), and why it never shows a score or the word "secure". Anything more is behind a login and
 * a verified asset. Off until the admin turns it on (public_check); a few checks per visitor address an hour and a
 * daily ceiling for everyone; the blocklist applies; nothing is stored.
 */
final class PublicCheck
{
    public static function enabled(): bool
    {
        return Settings::bool('enabled') && Settings::bool('public_check');
    }

    /** @return array{ok:bool,error?:string,domain?:string,rows?:array<int,array{0:string,1:string,2:string}>} */
    public static function run(string $input, string $visitor): array
    {
        if (!self::enabled()) {
            return ['ok' => false, 'error' => 'این بررسی در دسترس نیست.'];
        }
        $t = Net::parse(mb_substr($input, 0, 300));
        $domain = strtolower((string) ($t['value'] ?? ''));
        if (!empty($t['error']) || ($t['kind'] ?? '') !== 'domain' || $domain === '' || !str_contains($domain, '.')) {
            return ['ok' => false, 'error' => 'نام یک دامنه را بنویسید، مثل example.com'];
        }
        if (!RateLimit::hit('pubcheck:' . sha1($visitor), 5, 3600)) {
            return ['ok' => false, 'error' => 'در این ساعت چند بررسی انجام داده‌اید. کمی بعد دوباره امتحان کنید.'];
        }
        if (!RateLimit::hit('pubcheck:all', max(10, Settings::int('public_check_daily')), 86400)) {
            return ['ok' => false, 'error' => 'سقف بررسی‌های رایگان امروز پر شده است. فردا دوباره امتحان کنید.'];
        }
        if (Net::blocked('domain', $domain) !== '') {
            return ['ok' => false, 'error' => 'این دامنه بررسی نمی‌شود.'];
        }
        $apex = Net::apex($domain);
        $rows = [];
        $ns = Net::dns($apex, 'NS');
        if (!$ns && !Net::ips($domain)) {
            return ['ok' => false, 'error' => 'این دامنه در DNS پیدا نشد. املای آن را ببینید.'];
        }
        $rows[] = count($ns) >= 2 ? ['سرورهای نام (NS)', 'ok', Lang::t('{n} سرور نام دارد.', ['n' => Text::fa(count($ns))])]
            : ['سرورهای نام (NS)', 'warn', Lang::t('کمتر از دو سرور نام دیده شد؛ اگر همان یکی از کار بیفتد دامنه از دسترس می‌رود.')];
        $ips = Net::ips($domain);
        $rows[] = $ips ? ['نشانی سایت (A / AAAA)', 'ok', Lang::t('به {n} نشانی اشاره می‌کند.', ['n' => Text::fa(count($ips))])] : ['نشانی سایت (A / AAAA)', 'info', Lang::t('این نام نشانی IP ندارد.')];
        $mx = Net::dns($apex, 'MX');
        $rows[] = $mx ? ['ایمیل (MX)', 'ok', Lang::t('ایمیل این دامنه سرور دریافت دارد.')] : ['ایمیل (MX)', 'info', Lang::t('سرور دریافت ایمیل ندارد. حتی دامنه‌ی بی ایمیل هم SPF و DMARC می‌خواهد تا کسی به نامش ایمیل جعلی نفرستد.')];
        $spf = array_values(array_filter(Net::txt($apex), fn ($x) => stripos(trim($x, '"'), 'v=spf1') === 0));
        if (!$spf) {
            $rows[] = ['SPF', 'bad', Lang::t('رکورد SPF ندارد: هر کسی می‌تواند به نام این دامنه ایمیل بفرستد.')];
        } elseif (preg_match('/[+?]all\b/i', $spf[0]) || !preg_match('/[-~]all\b|redirect=/i', $spf[0])) {
            $rows[] = ['SPF', 'warn', Lang::t('رکورد SPF هست ولی جلوی جعل را نمی‌گیرد (پایانش ‎-all یا ‎~all نیست).')];
        } else {
            $rows[] = ['SPF', 'ok', Lang::t('رکورد SPF درست بسته شده است.')];
        }
        $dmarc = array_values(array_filter(Net::txt('_dmarc.' . $apex), fn ($x) => stripos(trim($x, '"'), 'v=DMARC1') === 0));
        if (!$dmarc) {
            $rows[] = ['DMARC', 'bad', Lang::t('رکورد DMARC ندارد: سرویس‌های ایمیل نمی‌دانند با ایمیل جعلی این دامنه چه کنند.')];
        } elseif (preg_match('~\bp\s*=\s*none~i', $dmarc[0])) {
            $rows[] = ['DMARC', 'warn', Lang::t('DMARC فقط نظارتی است (p=none): ایمیل جعلی گزارش می‌شود ولی رد نمی‌شود.')];
        } else {
            $rows[] = ['DMARC', 'ok', Lang::t('DMARC ایمیل جعلی را قرنطینه یا رد می‌کند.')];
        }
        $rows[] = Net::dns($apex, 'CAA') ? ['CAA', 'ok', Lang::t('مشخص کرده کدام مرجع می‌تواند برایش گواهی SSL صادر کند.')]
            : ['CAA', 'info', Lang::t('رکورد CAA ندارد: هر مرجع صدور گواهی می‌تواند برای این دامنه گواهی بدهد.')];
        return ['ok' => true, 'domain' => $domain, 'rows' => $rows];
    }
}
