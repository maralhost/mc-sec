<?php

declare(strict_types=1);

namespace McSec\Admin;

use McSec\Assets;
use McSec\Audit;
use McSec\Auth;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Net;
use McSec\Notify;
use McSec\Scans;
use McSec\Settings;
use McSec\Text;
use McSec\Trace;
use McSec\Verify;
use McSec\Worker;

/**
 * Admin pages inside addonmodules.php?module=mcsec&mcsa=<page>, POST mcsa_act=<action>.
 * Tiers (setting role_map): view sees everything; ops may approve verifications, grant credits, cancel/retry scans,
 * run the worker and test backends; settings may change settings, pricing and engines.
 * Every POST: the module's session CSRF token (mcsa_csrf) and the tier of the action. Inputs are html_entity_decode'd
 * (WHMCS escapes $_POST). Form field names never are page, tab, do or status (WHMCS uses them).
 */
final class Controller
{
    public const PAGES = ['overview' => 'نمای کلی', 'setup' => 'راه‌اندازی موتورها', 'pricing' => 'قیمت و پلن', 'credits' => 'قاعده‌ها و اعطا', 'codes' => 'کدها', 'assets' => 'دارایی‌ها و تأیید',
        'scans' => 'صف اسکن', 'settings' => 'تنظیمات', 'log' => 'گزارش فنی', 'changelog' => 'تغییرات نسخه‌ها'];

    private const ACTIONS = [
        'save_settings' => 'settings', 'save_engines' => 'settings', 'save_profiles' => 'settings', 'save_packs' => 'settings', 'save_rule' => 'settings', 'disable_rule' => 'settings', 'save_code' => 'settings', 'disable_code' => 'settings', 'save_custom' => 'settings', 'delete_custom' => 'settings',
        'test_engine' => 'ops', 'run_worker' => 'ops', 'grant' => 'ops', 'approve_asset' => 'ops', 'cancel_scan' => 'ops', 'retry_scan' => 'ops', 'scope_test' => 'ops',
    ];

    public static function handle(string $link): string
    {
        \McSec\Lang::set('fa'); // the panel is Persian
        $page = (string) ($_GET['mcsa'] ?? 'overview');
        if (!isset(self::PAGES[$page])) {
            $page = 'overview';
        }
        Views::$link = $link;
        $flash = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['mcsa_act'])) {
            $flash = self::post((string) $_POST['mcsa_act']);
            Settings::forget();
        }
        return Views::render($page, $flash);
    }

    private static function post(string $act): string
    {
        if (!Auth::checkCsrf((string) ($_POST['mcsa_csrf'] ?? ''))) {
            return 'err:فرم منقضی شده است؛ صفحه را تازه کنید.';
        }
        $tier = self::ACTIONS[$act] ?? null;
        if ($tier === null) {
            return 'err:این کار شناخته نشد.';
        }
        if (!Auth::adminCan($tier)) {
            return 'err:نقش شما اجازه‌ی این کار را ندارد (سطح لازم: ' . $tier . '). سطح نقش‌ها در تنظیمات «سطح نقش‌های مدیر» است.';
        }
        $in = fn (string $k): string => html_entity_decode(trim((string) ($_POST[$k] ?? '')), ENT_QUOTES, 'UTF-8');
        $int = fn (string $k): int => (int) Text::toAscii((string) ($_POST[$k] ?? '0'));
        try {
            switch ($act) {
                case 'save_settings':
                case 'save_engines':
                    $n = 0;
                    foreach (Settings::DEFS as $k => [$def, $type, $group]) {
                        if (!array_key_exists('set_' . $k, $_POST) && $type !== 'bool') {
                            continue;
                        }
                        if ($type === 'bool') {
                            if (!array_key_exists('has_' . $k, $_POST)) {
                                continue;
                            }
                            Settings::set($k, ($_POST['set_' . $k] ?? '') === '1' ? '1' : '0');
                        } elseif ($type === 'secret') {
                            $v = $in('set_' . $k);
                            if ($v === '' && ($_POST['clear_' . $k] ?? '') !== '1') {
                                continue; // empty = keep the stored secret
                            }
                            Settings::setSecret($k, ($_POST['clear_' . $k] ?? '') === '1' ? '' : $v);
                        } elseif ($type === 'int') {
                            Settings::set($k, (string) max(0, (int) Text::toAscii($in('set_' . $k))));
                        } elseif ($type === 'json') {
                            $j = json_decode($in('set_' . $k), true);
                            if (!is_array($j)) {
                                return 'err:مقدار «' . Settings::DEFS[$k][3] . '» JSON درست نیست.';
                            }
                            Settings::set($k, (string) json_encode($j, JSON_UNESCAPED_UNICODE));
                        } else {
                            $v = $in('set_' . $k);
                            if (in_array($k, ['oasm_url', 'osm_url', 'ai_base_url'], true) && $v !== '' && !preg_match('~^https?://[^\s]+$~i', $v)) {
                                return 'err:نشانی «' . Settings::DEFS[$k][3] . '» باید با http:// یا https:// شروع شود.';
                            }
                            Settings::set($k, $v);
                        }
                        $n++;
                    }
                    Audit::log(0, 'settings', $act, ['count' => $n]);
                    return 'ok:تنظیمات ذخیره شد.';
                case 'save_profiles':
                    $over = [];
                    foreach (Catalog::DEFAULTS + Catalog::custom() as $k => $p) {
                        $over[$k] = ['enabled' => ($_POST['pe'][$k] ?? '') === '1', 'free' => ($_POST['pf'][$k] ?? '') === '1',
                            'credits' => max(0, (int) Text::toAscii((string) ($_POST['pc'][$k] ?? $p['credits']))), 'label' => Text::name(html_entity_decode((string) ($_POST['pl'][$k] ?? ''), ENT_QUOTES, 'UTF-8'), 80)];
                        if (isset($p['workflow'])) {
                            $wf = preg_replace('~[^A-Za-z0-9_.-]~', '', (string) ($_POST['pw'][$k] ?? $p['workflow']));
                            $over[$k]['workflow'] = $wf !== '' ? $wf : $p['workflow'];
                        }
                    }
                    Settings::set('profiles', (string) json_encode($over, JSON_UNESCAPED_UNICODE));
                    Audit::log(0, 'settings', 'profiles', $over);
                    return 'ok:نوع‌های اسکن و قیمت‌ها ذخیره شد.';
                case 'save_custom':
                    $key = 'c_' . preg_replace('~[^a-z0-9_]~', '', strtolower(Text::toAscii((string) ($_POST['cp_key'] ?? ''))));
                    $tools = array_values(array_unique(array_filter(array_map('trim', explode(',', strtolower(Text::toAscii((string) ($_POST['cp_tools'] ?? ''))))), fn ($t) => isset(Catalog::TOOLS[$t]))));
                    $label = Text::name(html_entity_decode((string) ($_POST['cp_label'] ?? ''), ENT_QUOTES, 'UTF-8'), 80);
                    if (!preg_match('~^c_[a-z0-9_]{2,24}$~', $key) || $label === '') {
                        return 'err:کلید (۲ تا ۲۴ حرف لاتین کوچک، رقم یا _) و نام فارسی لازم است.';
                    }
                    if (!$tools) {
                        return 'err:دست‌کم یک ابزار شناخته‌شده لازم است: ' . implode('، ', array_keys(Catalog::TOOLS)) . '.';
                    }
                    $list = array_values(array_filter(Settings::json('custom_profiles'), fn ($c) => is_array($c) && ($c['key'] ?? '') !== $key));
                    if (count($list) >= 20) {
                        return 'err:بیش از ۲۰ نوع سفارشی پذیرفته نیست.';
                    }
                    $list[] = ['key' => $key, 'label' => $label, 'desc' => Text::name(html_entity_decode((string) ($_POST['cp_desc'] ?? ''), ENT_QUOTES, 'UTF-8'), 300), 'tools' => $tools,
                        'credits' => max(0, (int) Text::toAscii((string) ($_POST['cp_credits'] ?? '0'))), 'free' => ($_POST['cp_free'] ?? '') === '1', 'enabled' => ($_POST['cp_enabled'] ?? '') === '1'];
                    Settings::set('custom_profiles', (string) json_encode($list, JSON_UNESCAPED_UNICODE));
                    Settings::forget();
                    if (!isset(Catalog::custom()[$key])) {
                        // the tools share no asset kind (e.g. katana takes domains only, nmap IPs only)
                        Settings::set('custom_profiles', (string) json_encode(array_values(array_filter($list, fn ($c) => $c['key'] !== $key)), JSON_UNESCAPED_UNICODE));
                        return 'err:این ابزارها نوع دارایی مشترک ندارند (مثلاً Katana فقط دامنه و Nmap فقط IP می‌پذیرد).';
                    }
                    Audit::log(0, 'settings', 'custom_profile', ['key' => $key, 'tools' => $tools]);
                    return 'ok:نوع اسکن «' . $label . '» ذخیره شد.';
                case 'delete_custom':
                    $key = (string) ($_POST['cp_key'] ?? '');
                    if (Db::table('mod_mcsec_scans')->where('profile', $key)->whereIn('status', ['queued', 'running'])->exists()) {
                        return 'err:اسکنی از این نوع در صف یا در حال اجراست؛ پس از پایانش دوباره امتحان کنید.';
                    }
                    $list = Settings::json('custom_profiles');
                    $left = array_values(array_filter($list, fn ($c) => is_array($c) && ($c['key'] ?? '') !== $key));
                    if (count($left) === count($list)) {
                        return 'err:این نوع اسکن پیدا نشد.';
                    }
                    Settings::set('custom_profiles', (string) json_encode($left, JSON_UNESCAPED_UNICODE));
                    Audit::log(0, 'settings', 'custom_profile_delete', ['key' => $key]);
                    return 'ok:نوع اسکن برداشته شد. یافته‌ها و اسکن‌های قبلی آن می‌مانند.';
                case 'save_packs':
                    $packs = [];
                    foreach ((array) ($_POST['pk_key'] ?? []) as $i => $key) {
                        $key = preg_replace('~[^a-z0-9_-]~', '', strtolower((string) $key));
                        $cr = (int) Text::toAscii((string) ($_POST['pk_credits'][$i] ?? '0'));
                        $price = (float) str_replace(',', '', Text::toAscii((string) ($_POST['pk_price'][$i] ?? '0')));
                        if ($key === '' || $cr <= 0 || $price <= 0) {
                            continue;
                        }
                        $packs[] = ['key' => $key, 'credits' => $cr, 'price' => $price, 'label' => Text::name(html_entity_decode((string) ($_POST['pk_label'][$i] ?? ''), ENT_QUOTES, 'UTF-8'), 80)];
                    }
                    Settings::set('credit_packs', (string) json_encode($packs, JSON_UNESCAPED_UNICODE));
                    Audit::log(0, 'settings', 'packs', ['packs' => $packs]);
                    return 'ok:بسته‌های خرید ذخیره شد.';
                case 'save_rule':
                    $r = \McSec\Rules::save(['scope' => $int('rl_client') > 0 ? 'client' : 'group', 'target' => $int('rl_client') > 0 ? $int('rl_client') : $int('rl_group'), 'monthly' => $int('rl_monthly'), 'max_assets' => $int('rl_assets'),
                        'discount' => $int('rl_discount'), 'spend_pct' => ($_POST['rl_spend'] ?? '') === '' ? 100 : $int('rl_spend'), 'profiles' => $in('rl_profiles'), 'days' => $int('rl_days'), 'note' => $in('rl_note')], Auth::adminId());
                    return $r['ok'] ? 'ok:قاعده ذخیره شد و از همین حالا اعمال می‌شود. اعتبار ماهانه در هر ماه فقط یک بار داده می‌شود.' : 'err:' . $r['error'];
                case 'disable_rule':
                    return \McSec\Rules::disable($int('rule_id')) ? 'ok:قاعده برداشته شد. اعتباری که این ماه داده شده سر جایش می‌ماند.' : 'err:این قاعده پیدا نشد.';
                case 'save_code':
                    $r = \McSec\Codes::create(['kind' => $in('cd_kind'), 'code' => $in('cd_code'), 'value' => $int('cd_value'), 'bucket' => $in('cd_bucket'), 'max_uses' => $int('cd_max'), 'days' => $int('cd_days'),
                        'group_id' => $int('cd_group'), 'client_id' => $int('cd_client'), 'note' => $in('cd_note')], Auth::adminId());
                    return $r['ok'] ? 'ok:کد ' . $r['code'] . ' ساخته شد.' : 'err:' . $r['error'];
                case 'disable_code':
                    if (!\McSec\Codes::disable($int('code_id'))) {
                        return 'err:این کد پیدا نشد یا از پیش خاموش است.';
                    }
                    Audit::log(0, 'code', 'off ' . $int('code_id'));
                    return 'ok:کد خاموش شد. آنچه پیش‌تر با آن داده شده سر جایش می‌ماند.';
                case 'grant':
                    $cid = $int('grant_client');
                    $amount = $int('grant_amount');
                    $note = Text::name($in('grant_note'), 200);
                    if ($cid <= 0 || !\McSec\Whmcs::client($cid) || $amount <= 0) {
                        return 'err:شماره‌ی حساب و تعداد اعتبار را درست بنویسید.';
                    }
                    \McSec\Accounts::ensure($cid);
                    $bucket = $in('grant_bucket') === 'monthly' ? 'monthly' : 'paid';
                    $ok = Credits::credit($cid, $amount, $bucket, 'grant', 'grant:' . Auth::adminId() . ':' . bin2hex(random_bytes(6)), $note !== '' ? $note : 'اعتبار هدیه از پشتیبانی', Auth::adminId());
                    if ($ok) {
                        Audit::log($cid, 'grant', (string) $amount, ['bucket' => $bucket, 'note' => $note]);
                        Notify::event($cid, 'credits_added', ['credits' => $amount, 'note' => $note], 'grant:' . Clock::now() . ':' . $cid);
                    }
                    return $ok ? 'ok:' . Text::fa($amount) . ' اعتبار به حساب #' . $cid . ' افزوده شد.' : 'err:اعتبار افزوده نشد.';
                case 'approve_asset':
                    return Verify::adminApprove($int('asset_id'), Text::name($in('approve_note'), 200)) ? 'ok:دارایی تأیید شد و مشتری خبردار می‌شود.' : 'err:دارایی پیدا نشد.';
                case 'cancel_scan':
                    $s = Db::table('mod_mcsec_scans')->where('id', $int('scan_id'))->first();
                    if (!$s || !in_array($s->status, ['queued', 'running'], true)) {
                        return 'err:این اسکن در صف یا در حال اجرا نیست.';
                    }
                    if ($s->status === 'running') {
                        try {
                            Scans::engine((string) $s->engine)->cancel($s, Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first());
                        } catch (\Throwable $e) {
                            Trace::warn('admin', 'cancel', $e->getMessage());
                        }
                    }
                    Scans::fail($s, 'به دست پشتیبانی متوقف شد.', true);
                    return 'ok:اسکن متوقف و اعتبارش برگشت داده شد.';
                case 'scope_test':
                    // read-only: what the scope rules say about a target right now (one DNS lookup)
                    $t = Net::parse($in('target'));
                    if (isset($t['error'])) {
                        return 'err:' . $t['error'];
                    }
                    $sc = Net::screen($t['kind'], $t['value']);
                    $out = [$t['value'] . ' — ' . (Assets::KINDS[$t['kind']] ?? $t['kind'])];
                    if ($t['kind'] === 'domain') {
                        $out[] = 'IPها: ' . ($sc['ips'] ? implode('، ', $sc['ips']) : 'پیدا نشد');
                    } elseif (!Settings::bool('allow_private_ips') && !Net::isPublicIp(explode('/', $t['value'])[0])) {
                        $out[] = 'IP خصوصی یا رزروشده: پذیرفته نمی‌شود.';
                    }
                    $out[] = $sc['blocked'] !== '' ? 'ممنوع با قاعده‌ی «' . $sc['blocked'] . '»: افزوده و اسکن نمی‌شود.' : 'در فهرست ممنوع نیست.';
                    if ($sc['cdn'] === '') {
                        $out[] = 'پشت هیچ CDN شناخته‌شده‌ای نیست.';
                    } elseif ($t['kind'] === 'domain') {
                        $out[] = 'پشت CDN ' . Net::cdnLabel($sc['cdn']) . ' (' . $sc['cdn'] . '): ' . (Settings::bool('cdn_origin_scan') ? 'اسکن‌های درگاه و آسیب‌پذیری فقط روی IP اصلی تأییدشده‌ی مشتری.' : 'فقط بررسی سلامت پایه.');
                    } else {
                        $out[] = 'از سرورهای CDN ' . Net::cdnLabel($sc['cdn']) . ': به‌عنوان دارایی پذیرفته و اسکن نمی‌شود.';
                    }
                    return 'ok:' . implode("\n", $out);
                case 'retry_scan':
                    $s = Db::table('mod_mcsec_scans')->where('id', $int('scan_id'))->where('status', 'failed')->first();
                    $asset = $s ? Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first() : null;
                    if (!$s || !$asset) {
                        return 'err:اسکن ناموفقی با این شماره نیست.';
                    }
                    $r = Scans::queue((int) $s->client_id, $asset, (string) $s->profile, 0, 0, ['free' => true, 'admin' => Auth::adminId()]);
                    return $r['ok'] ? 'ok:اسکن تازه (رایگان) در صف قرار گرفت.' : 'err:' . $r['error'];
                case 'run_worker':
                    $r = Worker::run(40);
                    return $r === null ? 'err:کار پس‌زمینه همین حالا در حال اجراست.' : 'ok:کار پس‌زمینه اجرا شد: ' . mb_substr((string) json_encode($r, JSON_UNESCAPED_UNICODE), 0, 400);
                case 'test_engine':
                    $which = $in('engine');
                    if ($which === 'ai') {
                        if (!\McSec\Ai::configured()) {
                            return 'err:هوش مصنوعی روشن یا تنظیم نشده است.';
                        }
                        $r = \McSec\Ai::chat('Reply with JSON only.', 'Return {"ok":true,"lang":"fa"}', true, 50);
                        Settings::set('health_ai', (string) json_encode(['ok' => $r['ok'], 'at' => Clock::now(), 'message' => $r['ok'] ? 'پاسخ داد' : mb_substr($r['error'], 0, 200)], JSON_UNESCAPED_UNICODE));
                        return $r['ok'] ? 'ok:مدل پاسخ داد.' : 'err:مدل پاسخ نداد: ' . $r['error'];
                    }
                    if ($which === 'bots') {
                        $out = [];
                        foreach (['telegram', 'bale'] as $b) {
                            if (Settings::secret($b === 'telegram' ? 'telegram_token' : 'bale_token') !== '') {
                                $r = Notify::bot($b, 'getMe', []);
                                $out[] = $b . ': ' . ($r['ok'] ? '@' . ($r['json']['result']['username'] ?? '?') : $r['error']);
                            }
                        }
                        return $out ? 'ok:' . implode("\n", $out) : 'err:توکن هیچ رباتی تنظیم نشده است.';
                    }
                    if (!in_array($which, ['oasm', 'osmedeus', 'builtin'], true)) {
                        return 'err:موتور شناخته نشد.';
                    }
                    $h = Scans::engine($which)->health();
                    Settings::set('health_' . $which, (string) json_encode($h + ['at' => Clock::now()], JSON_UNESCAPED_UNICODE));
                    return ($h['ok'] ? 'ok:' : 'err:') . $h['message'];
            }
        } catch (\Throwable $e) {
            $ref = Trace::error('admin', $act, $e->getMessage(), Trace::exception($e));
            return 'err:خطا: ' . $e->getMessage() . ' (' . $ref . ')';
        }
        return 'err:این کار شناخته نشد.';
    }
}
