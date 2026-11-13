// Tests for the dashboard's pure helpers, lifted out of dashboard.html. Needs only Node:  node tests/test_dashboard.js
const fs = require("fs"), path = require("path"), assert = require("assert");
const html = fs.readFileSync(path.join(__dirname, "..", "dashboard.html"), "utf8");
const lift = name => { const m = html.match(new RegExp("^function " + name + "[(].*?^}", "ms")); assert(m, name + " not found"); return m[0]; };
const macQuery = new Function(lift("macQuery") + "; return macQuery;")();

// every common way of writing a hardware address comes down to the same bare hex
for (const q of ["aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "aabbccddeeff", "aa bb cc dd ee ff"]) assert.strictEqual(macQuery(q), "aabbccddeeff", q);
assert.strictEqual(macQuery("94-e6-86"), "94e686");          // part of one, as copied from the Deco app
assert.strictEqual(macQuery("0011.2233.4455"), "001122334455");
// things that are not hardware addresses are left to the ordinary text search
for (const q of ["192.168.68.52", "192.168", "cafe", "deco", "living room", "", "zz:zz"]) assert.strictEqual(macQuery(q), null, q);
console.log("dashboard helpers ok");
