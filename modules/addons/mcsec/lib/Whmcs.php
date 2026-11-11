<?php

declare(strict_types=1);

namespace McSec;

/**
 * The only place that reads WHMCS's own tables (tbl*) and calls localAPI. Reads are batched (about 13k client
 * accounts). Writes to WHMCS data happen only through localAPI and only through the calls listed in CLAUDE.md:
 * SendEmail (custom 'general' message) and CreateInvoice (credit packs). `noemail` is never sent.
 */
final class Whmcs
{
    /** Tests: fn(string $cmd, array $params): array */
    public static $api = null;

    /** The link of a user to a client account: owner flag and permission names, or null. */
    public static function link(int $userId, int $clientId): ?array
    {
        $r = Db::table('tblusers_clients')->where('auth_user_id', $userId)->where('client_id', $clientId)->first();
        if (!$r) {
            return null;
        }
        $perms = array_values(array_filter(array_map('trim', explode(',', (string) ($r->permissions ?? '')))));
        return ['owner' => (int) $r->owner === 1, 'perms' => $perms];
    }

    public static function client(int $clientId): ?object
    {
        static $cache = [];
        if (!array_key_exists($clientId, $cache)) {
            $cache[$clientId] = Db::table('tblclients')->where('id', $clientId)
                ->first(['id', 'firstname', 'lastname', 'companyname', 'email', 'groupid', 'currency', 'status']);
        }
        return $cache[$clientId];
    }

    public static function clientName(int $clientId): string
    {
        $c = self::client($clientId);
        if (!$c) {
            return '#' . $clientId;
        }
        $n = trim((string) $c->companyname) !== '' ? (string) $c->companyname : trim($c->firstname . ' ' . $c->lastname);
        return $n !== '' ? $n : (string) $c->email;
    }

    /** @param int[] $ids @return array<int,string> */
    public static function clientNames(array $ids): array
    {
        $out = [];
        foreach (array_chunk(array_values(array_unique(array_filter($ids))), 500) as $chunk) {
            foreach (Db::rows(Db::table('tblclients')->whereIn('id', $chunk)->select(['id', 'firstname', 'lastname', 'companyname', 'email'])) as $c) {
                $n = trim((string) $c->companyname) !== '' ? (string) $c->companyname : trim($c->firstname . ' ' . $c->lastname);
                $out[(int) $c->id] = $n !== '' ? $n : (string) $c->email;
            }
        }
        return $out;
    }

    /** @param int[] $ids @return array<int,string> user id => name (or e-mail) */
    public static function userNames(array $ids): array
    {
        $out = [];
        foreach (array_chunk(array_values(array_unique(array_filter($ids))), 500) as $chunk) {
            foreach (Db::rows(Db::table('tblusers')->whereIn('id', $chunk)->select(['id', 'first_name', 'last_name', 'email'])) as $u) {
                $n = trim($u->first_name . ' ' . $u->last_name);
                $out[(int) $u->id] = $n !== '' ? $n : (string) $u->email;
            }
        }
        return $out;
    }

    /** Services on the mcsec provisioning module (plans), for the admin's plan list. */
    public static function planProducts(): array
    {
        try {
            return Db::rows(Db::table('tblproducts')->where('servertype', 'mcsecplan')->select(['id', 'name']));
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function groupOf(int $clientId): int
    {
        return (int) (self::client($clientId)->groupid ?? 0);
    }

    /** @return array<int,string> id => name */
    public static function groups(): array
    {
        $out = [];
        foreach (Db::rows(Db::table('tblclientgroups')->orderBy('groupname')) as $g) {
            $out[(int) $g->id] = (string) $g->groupname;
        }
        return $out;
    }

    public static function currency(int $id): ?object
    {
        static $cache = [];
        if (!array_key_exists($id, $cache)) {
            $cache[$id] = Db::table('tblcurrencies')->where('id', $id)->first() ?: Db::table('tblcurrencies')->orderBy('id')->first();
        }
        return $cache[$id];
    }

    /** Domains this account has in WHMCS (registered domains and hosting services), lowercased, active only. @return string[] */
    public static function ownedDomains(int $clientId): array
    {
        $out = [];
        foreach (Db::rows(Db::table('tbldomains')->where('userid', $clientId)->whereIn('status', ['Active', 'Pending Transfer', 'Grace'])->select(['domain'])) as $d) {
            $out[] = strtolower(trim((string) $d->domain));
        }
        foreach (Db::rows(Db::table('tblhosting')->where('userid', $clientId)->whereIn('domainstatus', ['Active', 'Suspended'])->where('domain', '!=', '')->select(['domain'])) as $h) {
            $out[] = strtolower(trim((string) $h->domain));
        }
        return array_values(array_unique(array_filter($out)));
    }

    /** Dedicated and assigned IPs of this account's active services. @return string[] */
    public static function ownedIps(int $clientId): array
    {
        $cols = ['id'];
        foreach (['dedicatedip', 'assignedips'] as $c) {
            if (Db::hasColumn('tblhosting', $c)) {
                $cols[] = $c;
            }
        }
        if (count($cols) === 1) {
            return [];
        }
        $out = [];
        foreach (Db::rows(Db::table('tblhosting')->where('userid', $clientId)->whereIn('domainstatus', ['Active', 'Suspended'])->select($cols)) as $h) {
            foreach ([(string) ($h->dedicatedip ?? ''), (string) ($h->assignedips ?? '')] as $field) {
                foreach (preg_split('~[\s,;]+~', $field) ?: [] as $ip) {
                    $ip = trim($ip);
                    if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                        $out[] = strtolower($ip);
                    }
                }
            }
        }
        return array_values(array_unique($out));
    }

    /** E-mail through WHMCS's own mailer: a custom 'general' message (subject and HTML body). */
    public static function sendEmail(int $clientId, string $subject, string $html): array
    {
        // WHMCS parses {$...} merge fields in custom messages; neutralise braces from our content
        $subject = strtr($subject, ['{' => '(', '}' => ')']);
        $html = strtr($html, ['{' => '&#123;', '}' => '&#125;']);
        return self::api('SendEmail', ['id' => $clientId, 'customtype' => 'general', 'customsubject' => $subject, 'custommessage' => $html]);
    }

    /** An unpaid invoice for a credit pack; returns ['ok', 'invoice_id', 'error']. */
    public static function createInvoice(int $clientId, string $description, float $amount, int $dueDays): array
    {
        $due = date('Y-m-d', Clock::now() + max(0, $dueDays) * 86400);
        $r = self::api('CreateInvoice', [
            'userid' => $clientId, 'status' => 'Unpaid', 'sendinvoice' => true, 'date' => date('Y-m-d', Clock::now()), 'duedate' => $due,
            'itemdescription1' => $description, 'itemamount1' => number_format($amount, 2, '.', ''), 'itemtaxed1' => true,
        ]);
        return $r['ok'] ? ['ok' => true, 'invoice_id' => (int) ($r['data']['invoiceid'] ?? 0), 'error' => ''] : ['ok' => false, 'invoice_id' => 0, 'error' => $r['error']];
    }

    public static function invoice(int $invoiceId): ?object
    {
        return Db::table('tblinvoices')->where('id', $invoiceId)->first(['id', 'userid', 'status', 'total']);
    }

    public static function systemUrl(): string
    {
        $u = Db::whmcsSetting('SystemURL');
        return $u === '' ? '/' : rtrim($u, '/') . '/';
    }

    /** localAPI with the result normalised; failures go to the technical log. */
    public static function api(string $cmd, array $params): array
    {
        try {
            if (self::$api !== null) {
                $r = (self::$api)($cmd, $params);
            } elseif (function_exists('localAPI')) {
                $r = localAPI($cmd, $params);
            } else {
                return ['ok' => false, 'data' => [], 'error' => 'localAPI is not available'];
            }
        } catch (\Throwable $e) {
            Trace::error('whmcs', $cmd, $e->getMessage(), Trace::exception($e));
            return ['ok' => false, 'data' => [], 'error' => $e->getMessage()];
        }
        $ok = is_array($r) && ($r['result'] ?? '') === 'success';
        if (!$ok) {
            $msg = (string) ($r['message'] ?? 'unknown error');
            Trace::error('whmcs', $cmd, $msg, ['params' => $params, 'answer' => $r]);
            return ['ok' => false, 'data' => is_array($r) ? $r : [], 'error' => $msg];
        }
        return ['ok' => true, 'data' => $r, 'error' => ''];
    }
}
