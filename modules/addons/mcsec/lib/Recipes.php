<?php

declare(strict_types=1);

namespace McSec;

/**
 * Advanced mode: a customer's own scan («اسکن سفارشی»), a saved pipeline of OASM tools (mod_mcsec_recipes).
 * It is a scan profile like any other (key u<id>, Catalog::find), so everything a scan must pass still applies in
 * Scans::queue: ownership proof, the blocklist, CDN rules, the daily cap, credits. What the customer may choose is
 * narrow on purpose:
 *  - only tools the admin allowed (setting advanced_tools) that MC-Sec knows (Catalog::TOOLS) and that are set up;
 *  - no free text reaches a tool: each option is one of a few named choices (OPTIONS) that map to fixed settings, and
 *    a choice can only make a tool gentler or narrower than MC-Sec's own defaults, never faster;
 *  - the order of the tools is fixed here (finding pages first, then testing them), not chosen;
 *  - the cost is the sum of its tools' costs.
 * A recipe is only ever read for its own account: Catalog::forClient lists the account's own, and Scans::queue runs
 * only what that list allows.
 */
final class Recipes
{
    public const MAX_TOOLS = 4;
    /** Pipeline order: discovery before testing. */
    private const ORDER = ['gau', 'katana', 'ffuf', 'dirsearch', 'arjun', 'nmap', 'nuclei', 'zap', 'wpscan', 'acunetix'];
    /** Default credit cost of one tool in a recipe (admin override: setting advanced_tool_costs). */
    private const COSTS = ['gau' => 2, 'katana' => 4, 'ffuf' => 6, 'dirsearch' => 6, 'arjun' => 4, 'nmap' => 4, 'nuclei' => 6, 'zap' => 6, 'wpscan' => 6, 'acunetix' => 60];

    /**
     * tool => option => [label, choices: key => [label, settings]]. The first choice is the default (MC-Sec's own
     * settings, so it adds nothing). 'rate' => 'half' is resolved against the admin's rate when the scan starts.
     */
    public const OPTIONS = [
        'nuclei' => [
            'severity' => ['کدام شدت‌ها', ['all' => ['همه‌ی شدت‌ها', []], 'medium' => ['متوسط و بالاتر', ['severity' => ['medium', 'high', 'critical']]], 'high' => ['فقط بالا و بحرانی', ['severity' => ['high', 'critical']]]]],
            'speed' => ['سرعت', ['normal' => ['عادی', []], 'slow' => ['آهسته (برای سرور ضعیف)', ['rate' => 'half', 'concurrency' => 2]]]],
        ],
        'katana' => [
            'depth' => ['عمق خزیدن', ['3' => ['۳ سطح', []], '2' => ['۲ سطح', ['depth' => 2]], '1' => ['فقط صفحه‌ی اول و پیوندهایش', ['depth' => 1]]]],
        ],
        'nmap' => [
            'ports' => ['درگاه‌ها', ['1000' => ['۱۰۰۰ درگاه رایج', []], '100' => ['۱۰۰ درگاه رایج (سریع‌تر)', ['topPorts' => 100]]]],
        ],
        'ffuf' => [
            'speed' => ['سرعت', ['normal' => ['عادی', []], 'slow' => ['آهسته (برای سرور ضعیف)', ['rate' => 'half', 'threads' => 2]]]],
        ],
    ];

    /** Whether this account may build and run its own scans. */
    public static function allowed(int $clientId): bool
    {
        if (!Settings::bool('advanced_enabled')) {
            return false;
        }
        return !Settings::bool('advanced_plan_only') || Plans::active($clientId) !== [];
    }

    /** Tools a customer may pick now: allowed by the admin, known, and with their key in place. @return array<string,array> */
    public static function tools(): array
    {
        $out = [];
        $allow = array_map('strtolower', Settings::csv('advanced_tools'));
        foreach (self::ORDER as $name) {
            $def = Catalog::TOOLS[$name] ?? null;
            if (!$def || !in_array($name, $allow, true) || (isset($def['needs']) && Settings::secret($def['needs']) === '')) {
                continue;
            }
            $out[$name] = $def + ['credits' => self::toolCost($name)];
        }
        return $out;
    }

    public static function toolCost(string $name): int
    {
        $over = Settings::json('advanced_tool_costs')[$name] ?? null;
        return max(0, (int) (is_numeric($over) ? $over : (self::COSTS[$name] ?? 6)));
    }

    public static function key(int $id): string
    {
        return 'u' . $id;
    }

    public static function idOf(string $key): int
    {
        return preg_match('~^u([1-9][0-9]{0,8})$~', $key, $m) ? (int) $m[1] : 0;
    }

    /** One recipe of one account. */
    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_recipes')->where('id', $id)->where('client_id', $clientId)->where('status', 'active')->first() : null;
    }

    /** @return object[] the account's own recipes, newest first */
    public static function forClient(int $clientId): array
    {
        return Db::rows(Db::table('mod_mcsec_recipes')->where('client_id', $clientId)->where('status', 'active')->orderByDesc('id')->limit(50));
    }

    /**
     * A recipe as a scan profile. $row may be a removed one (old scans still show their name and can be collected);
     * 'enabled' says whether it can start a new scan.
     */
    public static function profile(object $row): array
    {
        $tools = array_values(array_filter(explode(',', (string) $row->tools), fn ($t) => isset(Catalog::TOOLS[$t])));
        $kinds = ['domain', 'ip', 'cidr'];
        $cost = 0;
        $live = self::tools();
        $ok = $tools !== [];
        foreach ($tools as $t) {
            $kinds = array_values(array_intersect($kinds, Catalog::TOOLS[$t]['kinds']));
            $cost += self::toolCost($t);
            $ok = $ok && isset($live[$t]);
        }
        $chosen = Db::decode((string) $row->options, []);
        $options = [];
        $said = [];
        foreach ($tools as $t) {
            foreach (self::OPTIONS[$t] ?? [] as $opt => [$label, $choices]) {
                $c = (string) ($chosen[$t][$opt] ?? '');
                if (isset($choices[$c]) && $choices[$c][1] !== []) {
                    $options[$t] = ($options[$t] ?? []) + $choices[$c][1];
                    $said[] = Catalog::TOOLS[$t]['label'] . ': ' . Lang::t($choices[$c][0]);
                }
            }
        }
        $p = [
            'key' => self::key((int) $row->id), 'label' => (string) $row->name, 'engine' => 'oasm', 'tools' => $tools, 'options' => $options, 'credits' => $cost, 'kinds' => $kinds,
            'free' => false, 'enabled' => $ok && $kinds !== [] && $row->status === 'active' && self::allowed((int) $row->client_id), 'eta' => 'بسته به ابزارها', 'icon' => 'layers',
            'recipe' => (int) $row->id, 'owner' => (int) $row->client_id,
            // the arrow points the way the page reads
            'desc' => Lang::t('اسکن سفارشی شما: {tools}', ['tools' => implode(Lang::fa() ? ' ← ' : ' → ', array_map(fn ($t) => Catalog::TOOLS[$t]['label'], $tools))]) . ($said ? ' (' . Lang::join($said) . ')' : ''),
        ];
        $p['depth'] = Catalog::risk($p) === 'heavy' ? 4 : 3;
        return $p;
    }

    /** The profile behind a key u<id>, whoever owns it (callers check the owner; Catalog::forClient lists only one's own). */
    public static function find(string $key): ?array
    {
        $id = self::idOf($key);
        $row = $id > 0 ? Db::table('mod_mcsec_recipes')->where('id', $id)->first() : null;
        return $row ? self::profile($row) : null;
    }

    /**
     * Creates or changes a recipe. $in: id (0 = new), name, tools (names), options (tool => option => choice key).
     * @return array{ok:bool,error?:string,id?:int}
     */
    public static function save(array $who, array $in): array
    {
        $cid = (int) $who['client_id'];
        if (!self::allowed($cid)) {
            return ['ok' => false, 'error' => Settings::bool('advanced_enabled') ? 'اسکن سفارشی برای حساب‌های دارای پلن است.' : 'اسکن سفارشی فعلاً در دسترس نیست.'];
        }
        $name = Text::name((string) ($in['name'] ?? ''), 80);
        if (mb_strlen($name) < 2) {
            return ['ok' => false, 'error' => 'برای اسکن خودتان یک نام بنویسید (مثلاً «بررسی هفتگی فروشگاه»).'];
        }
        $live = self::tools();
        $picked = array_map('strval', (array) ($in['tools'] ?? []));
        $tools = array_values(array_filter(array_keys($live), fn ($t) => in_array($t, $picked, true))); // fixed order, known tools only
        if (!$tools) {
            return ['ok' => false, 'error' => 'دست‌کم یک ابزار را انتخاب کنید.'];
        }
        if (count($tools) > self::MAX_TOOLS) {
            return ['ok' => false, 'error' => Lang::t('هر اسکن سفارشی حداکثر {n} ابزار دارد. اسکن بزرگ‌تر را به دو اسکن بشکنید.', ['n' => Text::fa(self::MAX_TOOLS)])];
        }
        $kinds = ['domain', 'ip', 'cidr'];
        foreach ($tools as $t) {
            $kinds = array_values(array_intersect($kinds, $live[$t]['kinds']));
        }
        if (!$kinds) {
            return ['ok' => false, 'error' => 'این ابزارها با هم روی یک دارایی اجرا نمی‌شوند: بعضی فقط دامنه می‌پذیرند و بعضی فقط IP. ترکیب دیگری انتخاب کنید.'];
        }
        // only named choices are kept; anything else in the request is dropped
        $options = [];
        foreach ($tools as $t) {
            foreach (self::OPTIONS[$t] ?? [] as $opt => [, $choices]) {
                $c = (string) ($in['options'][$t][$opt] ?? '');
                if (isset($choices[$c]) && $c !== (string) array_key_first($choices)) {
                    $options[$t][$opt] = $c;
                }
            }
        }
        $row = ['name' => $name, 'tools' => implode(',', $tools), 'options' => Db::json($options), 'updated_at' => Clock::now()];
        $id = (int) ($in['id'] ?? 0);
        if ($id > 0) {
            if (!self::get($cid, $id)) {
                return ['ok' => false, 'error' => 'این اسکن سفارشی پیدا نشد.'];
            }
            Db::table('mod_mcsec_recipes')->where('id', $id)->where('client_id', $cid)->update($row);
        } else {
            $max = max(1, Settings::int('advanced_max'));
            if (Db::table('mod_mcsec_recipes')->where('client_id', $cid)->where('status', 'active')->count() >= $max) {
                return ['ok' => false, 'error' => Lang::t('هر حساب تا {n} اسکن سفارشی دارد. یکی را حذف کنید.', ['n' => Text::fa($max)])];
            }
            $id = (int) Db::table('mod_mcsec_recipes')->insertGetId($row + ['client_id' => $cid, 'status' => 'active', 'created_by' => (int) $who['user_id'], 'created_at' => Clock::now()]);
        }
        Audit::log($cid, 'recipe', $name, ['id' => $id, 'tools' => $tools, 'options' => $options], (int) $who['user_id']);
        return ['ok' => true, 'id' => $id];
    }

    /** Removes a recipe (kept, switched off, so old scans keep their name); its schedules pause at their next run. */
    public static function remove(array $who, int $id): array
    {
        $r = self::get((int) $who['client_id'], $id);
        if (!$r) {
            return ['ok' => false, 'error' => 'این اسکن سفارشی پیدا نشد.'];
        }
        Db::table('mod_mcsec_recipes')->where('id', $id)->where('client_id', (int) $who['client_id'])->update(['status' => 'removed', 'updated_at' => Clock::now()]);
        Audit::log((int) $who['client_id'], 'recipe', Lang::t('حذف {name}', ['name' => $r->name]), ['id' => $id], (int) $who['user_id']);
        return ['ok' => true];
    }

    /**
     * The settings a recipe's choices add to a tool, on top of MC-Sec's own ($base). A choice may only narrow or slow
     * a tool down: a rate is at most half the admin's, numbers never rise above the base.
     */
    public static function apply(array $base, array $extra): array
    {
        foreach ($extra as $k => $v) {
            if ($k === 'rate') {
                foreach (['rateLimit', 'rate'] as $rk) {
                    if (isset($base[$rk])) {
                        $base[$rk] = max(1, intdiv((int) $base[$rk], 2));
                    }
                }
            } elseif (is_int($v) && isset($base[$k]) && is_numeric($base[$k])) {
                $base[$k] = min((int) $base[$k], $v);
            } elseif ($k === 'severity' && is_array($v)) {
                $base[$k] = array_values(array_intersect((array) ($base[$k] ?? $v), $v));
            } elseif ($k === 'tags' && is_array($v)) {
                // fewer templates is always gentler: only plain tag names, and never a tag the admin excluded
                $tags = array_values(array_filter(array_map('strval', $v), fn ($t) => preg_match('~^[a-z0-9_-]{1,40}$~', $t) === 1 && !in_array($t, (array) ($base['excludeTags'] ?? []), true)));
                if ($tags) {
                    $base['tags'] = $tags;
                }
            }
        }
        return $base;
    }
}
