// Tests for the dashboard's pure helpers, lifted out of dashboard.html. Needs only Node:  node tests/test_dashboard.js
const fs = require("fs"), path = require("path"), assert = require("assert");
const html = fs.readFileSync(path.join(__dirname, "..", "dashboard.html"), "utf8").replace(/\r\n/g, "\n");
// a whole top-level function, or a top-level const (to the first line that ends its statement)
const fn = name => { const m = html.match(new RegExp("^(?:async )?function " + name + "[(].*?^}", "ms")); assert(m, name + " not found"); return m[0]; };
const konst = name => { const m = html.match(new RegExp("^const " + name + " = .*?;$", "ms")); assert(m, name + " not found"); return m[0]; };
const load = (code, names) => new Function(code + "; return {" + names.join(",") + "};")();

// ---- searching by hardware address ----
const {macQuery} = load(fn("macQuery"), ["macQuery"]);
// every common way of writing a hardware address comes down to the same bare hex
for (const q of ["aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "aabbccddeeff", "aa bb cc dd ee ff"]) assert.strictEqual(macQuery(q), "aabbccddeeff", q);
assert.strictEqual(macQuery("94-e6-86"), "94e686");          // part of one, as copied from the Deco app
assert.strictEqual(macQuery("0011.2233.4455"), "001122334455");
// things that are not hardware addresses are left to the ordinary text search
for (const q of ["192.168.68.52", "192.168", "cafe", "deco", "living room", "", "zz:zz"]) assert.strictEqual(macQuery(q), null, q);

// ---- which picture a device gets ----
const {kindOf} = load(konst("KINDS") + fn("kindOf"), ["kindOf"]);
const kind = d => kindOf({label:"", deco_name:"", mdns:"", hostname:"", hint:"", vendor:"", infra:"", ...d});
assert.strictEqual(kind({infra:"mesh", label:"Office TV"}), "router");                 // what it is on the network comes first
assert.strictEqual(kind({label:"Living room TV"}), "tv");
assert.strictEqual(kind({deco_name:"Xbox"}), "console");
assert.strictEqual(kind({hostname:"Doorbell"}), "camera");
assert.strictEqual(kind({label:"Hallway plug"}), "home");
assert.strictEqual(kind({hint:"Apple device (iPhone, iPad or Mac)"}), "phone");        // a guess that lists several things: a phone is likeliest
assert.strictEqual(kind({vendor:"Raspberry Pi Trading Ltd"}), "computer");
assert.strictEqual(kind({label:"Thing", hint:"Printer"}), "printer");                  // its name says nothing, so the guess decides
assert.strictEqual(kind({}), "unknown");

// ---- words for what the Deco reports ----
const {connName, nodeName} = load(konst("CONN") + konst("connName") + konst("nodeName"), ["connName", "nodeName"]);
assert.strictEqual(connName("band2_4"), "Wi-Fi 2.4 GHz");
assert.strictEqual(connName("something-new"), "something-new");                         // never hidden, even if not yet known
assert.strictEqual(connName(""), "");
assert.strictEqual(nodeName({node:"Office"}), "Office Deco");
assert.strictEqual(nodeName({node:"Upstairs deco"}), "Upstairs deco");
assert.strictEqual(nodeName({}), "");

// ---- which entries in the to-do list are security warnings ----
const {urgentKind} = load(konst("urgentKind"), ["urgentKind"]);
assert.deepStrictEqual(["impostor", "threat", "new", "silent", "tracking"].map(kind => urgentKind({kind})), [true, true, false, false, false]);

// ---- "how long ago", as shown all over the page ----
const {ago} = load(fn("ago"), ["ago"]);
const secs = n => Date.now() / 1000 - n;
assert.strictEqual(ago(0), "never");
assert.strictEqual(ago(secs(30)), "just now");
assert.strictEqual(ago(secs(600)), "10 min ago");
assert.strictEqual(ago(secs(3 * 3600)), "3 h ago");

console.log("dashboard helpers ok");
