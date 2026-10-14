// tagcess interface behaviour that HTML alone cannot do. It is loaded in <head> without defer so
// the remembered theme applies before the first paint; everything else is delegated listeners.
// Pages never add their own script: they use the data- attributes below through internal/web/ui.
//
//   data-theme-toggle        switches dark/light and remembers it in this browser
//   data-dialog-open="id"    opens <dialog id> as a modal (ui.Dialog)
//   data-dialog-close        closes the enclosing dialog
//   data-copy="text"         copies text to the clipboard (ui.Secret)
//   details.menu             closes when the user clicks outside it (ui.Menu)
//   data-nav-toggle          opens/closes the sidebar drawer on narrow screens (Layout); Escape and a
//                            click outside close it again
//   table[data-sortable]     header cells become sort buttons with aria-sort (ui.ListTable)
//   data-table-search        filters the rows of the enclosing [data-table] by their text; the count
//                            goes to [data-table-count], [data-table-none] shows when nothing matches
//   data-sort="key"          on a cell: the value its column sorts by instead of the text
//   data-nosort              on a header cell: the column is not sortable
//   textarea[data-code-editor] loads /static/editor.js (CodeMirror 6) once, only on pages that have
//                            one; without it the textarea stays a plain, working form field
//   [data-tip]               info tooltip (ui.Tip): CSS shows it on hover/focus, Escape hides it
//   [data-msg]               live field check: on leaving a field (and while fixing it) the browser's
//                            check (type, pattern, required) and data-line-pattern (every non-empty
//                            line of a textarea) decide; the data-msg text is shown under the field
//   [data-file-into="id"]    file picker that reads a small text file into textarea#id (ui.FileInto)
//   [data-multi]             multi-value field (ui.MultiSelect): the textarea/input becomes chips plus
//                            an input that suggests the <datalist> values; the plain field stays the
//                            form value (joined with data-multi-sep), so the POST is unchanged
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "tagcess-theme";

  function stored() {
    try { return localStorage.getItem(KEY); } catch (_) { return null; }
  }
  function remember(theme) {
    try { localStorage.setItem(KEY, theme); } catch (_) { /* private mode: not remembered */ }
  }
  if (stored() === "light") root.dataset.theme = "light";
  // Marks that script runs, so the shell may hide the narrow-screen menu behind its button; without
  // script the menu stays visible.
  root.classList.add("js");

  var narrow = window.matchMedia("(max-width: 800px)");
  var navReturnFocus = null;
  var focusables = 'a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])';
  function setNav(open) {
    var shell = document.querySelector(".shell");
    var btn = document.querySelector("[data-nav-toggle]");
    var sidebar = document.querySelector("#sidebar");
    var main = document.querySelector(".main");
    if (!shell || !btn || !sidebar || !main) return;
    open = open && narrow.matches;
    var wasOpen = shell.classList.contains("nav-open");
    if (open && !wasOpen) navReturnFocus = document.activeElement;
    shell.classList.toggle("nav-open", open);
    root.classList.toggle("nav-locked", open);
    main.inert = open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open && !wasOpen) {
      // Wait for the drawer's visibility transition to start before focusing it.
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          if (!shell.classList.contains("nav-open") || !narrow.matches) return;
          var first = sidebar.querySelector("a");
          if (first) first.focus();
        });
      });
    } else if (!open && wasOpen && narrow.matches) {
      var previous = navReturnFocus && navReturnFocus.isConnected ? navReturnFocus : btn;
      previous.focus();
    }
    if (!open) navReturnFocus = null;
  }
  narrow.addEventListener("change", function () { if (!narrow.matches) setNav(false); });

  // Popovers live in the browser top layer, outside table/card overflow clipping. The details
  // markup stays a working disclosure when script or the Popover API is unavailable.
  function closeMenu(menu, restoreFocus) {
    var list = menu.querySelector(".menu-list");
    if (list && list.hasAttribute("popover")) list.hidePopover();
    menu.removeAttribute("open");
    var summary = menu.querySelector("summary");
    if (summary) {
      summary.setAttribute("aria-expanded", "false");
      if (restoreFocus) summary.focus();
    }
  }
  function placeMenu(menu) {
    var list = menu.querySelector(".menu-list");
    if (!list || !list.hasAttribute("popover")) return;
    var anchor = menu.querySelector("summary").getBoundingClientRect();
    var size = list.getBoundingClientRect();
    var margin = 8, gap = 6;
    var top = anchor.bottom + gap;
    if (top + size.height > window.innerHeight - margin) top = anchor.top - gap - size.height;
    list.style.left = Math.max(margin, Math.min(anchor.right - size.width, window.innerWidth - size.width - margin)) + "px";
    list.style.top = Math.max(margin, Math.min(top, window.innerHeight - size.height - margin)) + "px";
  }
  function openMenu(menu, focusFirst) {
    document.querySelectorAll("details.menu[open]").forEach(function (other) { if (other !== menu) closeMenu(other, false); });
    menu.setAttribute("open", "");
    var list = menu.querySelector(".menu-list");
    if (list && list.hasAttribute("popover")) { list.showPopover(); placeMenu(menu); }
    menu.querySelector("summary").setAttribute("aria-expanded", "true");
    if (focusFirst) {
      var first = list && list.querySelector("a, button:not([disabled])");
      if (first) first.focus();
    }
  }
  function placeOpenMenus() {
    document.querySelectorAll("details.menu[open]").forEach(placeMenu);
  }
  window.addEventListener("resize", placeOpenMenus);
  document.addEventListener("scroll", placeOpenMenus, true);
  var dialogReturnFocus = new WeakMap();
  document.addEventListener("close", function (e) {
    var previous = dialogReturnFocus.get(e.target);
    if (previous && previous.isConnected) previous.focus();
    dialogReturnFocus.delete(e.target);
  }, true);
  document.addEventListener("keydown", function (e) {
    var tip = e.key === "Escape" && e.target instanceof Element && e.target.closest("[data-tip]");
    if (tip) { tip.setAttribute("data-tip-hidden", ""); return; }
    if (e.key === "Escape") {
      if (document.querySelector(".shell.nav-open")) { e.preventDefault(); setNav(false); }
      document.querySelectorAll("details.menu[open]").forEach(function (menu) { e.preventDefault(); closeMenu(menu, true); });
    }
    var summary = e.target instanceof Element && e.target.closest("summary");
    if (e.key === "ArrowDown" && summary && summary.closest("details.menu")) {
      e.preventDefault(); openMenu(summary.closest("details.menu"), true);
    }
    if (e.key === "Tab" && document.querySelector(".shell.nav-open")) {
      var sidebar = document.querySelector("#sidebar");
      var stops = Array.prototype.filter.call(sidebar.querySelectorAll(focusables), function (el) { return !el.disabled && el.getAttribute("aria-hidden") !== "true"; });
      var first = stops[0], last = stops[stops.length - 1];
      if (stops.length && (e.shiftKey ? document.activeElement === first : document.activeElement === last)) {
        e.preventDefault(); (e.shiftKey ? last : first).focus();
      }
    }
  });

  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!(t instanceof Element)) return;

    document.querySelectorAll("details.menu[open]").forEach(function (m) {
      if (!m.contains(t)) closeMenu(m, false);
    });

    var summary = t.closest("summary");
    var menu = summary && summary.closest("details.menu");
    if (menu && menu.querySelector(".menu-list").hasAttribute("popover")) {
      e.preventDefault();
      if (menu.hasAttribute("open")) closeMenu(menu, false);
      else openMenu(menu, e.detail === 0);
      return;
    }
    var sourceMenu = t.closest("details.menu");
    var returnFocus = sourceMenu && sourceMenu.querySelector("summary");
    if (sourceMenu && t.closest("a, button")) closeMenu(sourceMenu, false);

    if (t.closest("[data-nav-toggle]")) {
      setNav(!document.querySelector(".shell.nav-open"));
      return;
    }
    if (document.querySelector(".shell.nav-open") && !t.closest(".sidebar")) setNav(false);

    var sortBtn = t.closest(".th-sort");
    if (sortBtn) {
      sortBy(sortBtn.closest("th"));
      return;
    }

    if (t.closest("[data-theme-toggle]")) {
      var next = root.dataset.theme === "light" ? "dark" : "light";
      root.dataset.theme = next;
      remember(next);
      return;
    }
    var opener = t.closest("[data-dialog-open]");
    if (opener) {
      var dlg = document.getElementById(opener.getAttribute("data-dialog-open"));
      if (dlg && dlg.showModal) {
        e.preventDefault();
        dialogReturnFocus.set(dlg, returnFocus || opener);
        dlg.showModal();
      }
      return;
    }
    if (t.closest("[data-dialog-close]")) {
      var open = t.closest("dialog");
      if (open) {
        e.preventDefault();
        open.close();
      }
      return;
    }
    if (t instanceof HTMLDialogElement) {
      // A backdrop click lands on the dialog element itself, outside its box; its padding does too,
      // so only a point outside the box closes it.
      var r = t.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) t.close();
      return;
    }
    var copy = t.closest("[data-copy]");
    if (copy) {
      var label = copy.querySelector("[data-copy-label]");
      var secret = copy.closest(".secret");
      var status = secret && secret.querySelector("[data-copy-status]");
      function feedback(ok) {
        if (label) label.textContent = ok ? "Kopyalandı" : "Tekrar dene";
        if (status) status.textContent = ok ? "Kopyalandı." : "Kopyalanamadı. Tekrar deneyin veya metni seçip kopyalayın.";
      }
      if (!navigator.clipboard || !navigator.clipboard.writeText) { feedback(false); return; }
      // Clear the live region before each attempt so a repeated result is announced too.
      if (status) status.textContent = "";
      Promise.resolve().then(function () {
        return navigator.clipboard.writeText(copy.getAttribute("data-copy"));
      }).then(function () { feedback(true); }, function () { feedback(false); });
    }
  });
  // A hidden tooltip comes back the next time its button gets focus or the pointer. With script the
  // tooltip is placed in the viewport (fixed), so a scrolling table or card cannot clip it.
  function showTip(e) {
    var tip = e.target instanceof Element && e.target.closest("[data-tip]");
    if (!tip) return;
    tip.removeAttribute("data-tip-hidden");
    var btn = tip.querySelector(".tip-btn"), body = tip.querySelector(".tip-body");
    if (!btn || !body || !btn.getBoundingClientRect) return;
    var r = btn.getBoundingClientRect();
    var width = Math.min(340, window.innerWidth - 16);
    body.style.position = "fixed";
    body.style.maxWidth = width + "px";
    body.style.left = Math.max(8, Math.min(r.left - 8, window.innerWidth - width - 8)) + "px";
    body.style.top = (r.bottom + 6) + "px";
  }
  document.addEventListener("focusin", showTip);
  document.addEventListener("mouseover", showTip);

  // ---- ui.MultiSelect: chips over the plain field ----
  function multiValues(field, sep) {
    var parts = sep === "\n" ? field.value.split("\n") : field.value.split(sep.trim() || sep);
    var out = [];
    parts.forEach(function (p) {
      p = p.trim();
      if (p !== "" && out.indexOf(p) === -1) out.push(p);
    });
    return out;
  }
  function enhanceMulti(box) {
    var field = box.querySelector("textarea, input");
    if (!field || box.querySelector(".multi-box") || field.disabled) return;
    var sep = field.getAttribute("data-multi-sep") || "\n";
    var values = multiValues(field, sep);
    var required = field.required;
    var wrap = document.createElement("div");
    wrap.className = "multi-box";
    var list = document.createElement("span");
    list.setAttribute("role", "list");
    var input = document.createElement("input");
    input.type = "text";
    input.className = "multi-in";
    input.autocomplete = "off";
    var listID = field.getAttribute("data-multi-list");
    if (listID) input.setAttribute("list", listID);
    // The visible <label for> and the help text now name the input the person types into.
    if (field.id) { input.id = field.id; field.id = field.id + "-value"; }
    ["aria-label", "aria-describedby", "aria-invalid", "placeholder"].forEach(function (a) {
      if (field.hasAttribute(a)) input.setAttribute(a, field.getAttribute(a));
    });
    var status = document.createElement("span");
    status.className = "sr-only";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    function sync() {
      field.value = values.join(sep === "\n" ? "\n" : sep);
      input.required = required && values.length === 0;
    }
    function render() {
      while (list.firstChild) list.removeChild(list.firstChild);
      values.forEach(function (v, i) {
        var chip = document.createElement("span");
        chip.className = "chip";
        chip.setAttribute("role", "listitem");
        chip.appendChild(document.createTextNode(v));
        var x = document.createElement("button");
        x.type = "button";
        x.className = "chip-x";
        x.setAttribute("aria-label", v + " kaldır");
        x.textContent = "×";
        x.addEventListener("click", function () {
          values.splice(i, 1);
          sync(); render();
          status.textContent = v + " kaldırıldı";
          input.focus();
        });
        chip.appendChild(x);
        list.appendChild(chip);
      });
    }
    function add(raw) {
      var added = [];
      // A textarea field is one value per line; a value may itself contain commas (tag:web:80,443).
      raw.split(sep === "\n" ? "\n" : (sep.trim() || sep)).forEach(function (v) {
        v = v.trim();
        if (v !== "" && values.indexOf(v) === -1) { values.push(v); added.push(v); }
      });
      input.value = "";
      if (added.length) { sync(); render(); status.textContent = added.join(", ") + " eklendi"; }
    }
    input.addEventListener("keydown", function (e) {
      if ((e.key === "Enter" || e.key === ",") && input.value.trim() !== "") { e.preventDefault(); add(input.value); }
      else if (e.key === "Enter") e.preventDefault();
      else if (e.key === "Backspace" && input.value === "" && values.length) {
        var v = values.pop(); sync(); render(); status.textContent = v + " kaldırıldı";
      }
    });
    // A value picked from the suggestions, or typed and left, is added too.
    input.addEventListener("change", function () { if (input.value.trim() !== "") add(input.value); });
    wrap.addEventListener("click", function (e) { if (e.target === wrap) input.focus(); });
    // Text typed but not yet turned into a chip is still sent.
    if (field.form) field.form.addEventListener("submit", function () { if (input.value.trim() !== "") add(input.value); });
    field.required = false;
    field.hidden = true;
    wrap.appendChild(list);
    wrap.appendChild(input);
    box.insertBefore(wrap, field);
    box.appendChild(status);
    sync(); render();
  }

  // ---- live field checks (ui.In{Pattern,Msg}, ui.TA{LinePattern,Msg}) ----
  function lineProblem(el) {
    var src = el.getAttribute("data-line-pattern");
    if (!src) return "";
    var re;
    try { re = new RegExp("^(?:" + src + ")$"); } catch (_) { return ""; }
    var lines = el.value.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line !== "" && !re.test(line)) return (i + 1) + ". satır: ";
    }
    return "";
  }
  function fieldError(el, create) {
    var id = el.id ? el.id + "-err" : "";
    var box = id && document.getElementById(id);
    if (!box && create && id) {
      box = document.createElement("p");
      box.className = "field-err";
      box.id = id;
      el.insertAdjacentElement("afterend", box);
      var by = (el.getAttribute("aria-describedby") || "").split(" ").filter(Boolean);
      if (by.indexOf(id) === -1) { by.push(id); el.setAttribute("aria-describedby", by.join(" ")); }
    }
    return box;
  }
  function checkField(el, show) {
    var line = lineProblem(el);
    if (el.setCustomValidity) el.setCustomValidity(line ? line + el.getAttribute("data-msg") : "");
    var ok = el.checkValidity ? el.checkValidity() : line === "";
    if (ok) {
      el.removeAttribute("aria-invalid");
      var box = fieldError(el, false);
      if (box) box.textContent = "";
      return;
    }
    if (!show) return;
    el.setAttribute("aria-invalid", "true");
    var b = fieldError(el, true);
    if (b) b.textContent = line + el.getAttribute("data-msg");
  }
  document.addEventListener("focusout", function (e) {
    var t = e.target;
    if (t instanceof Element && t.matches("[data-msg]") && t.value !== "") checkField(t, true);
  });
  document.addEventListener("input", function (e) {
    var t = e.target;
    if (t instanceof Element && t.matches("[data-msg]")) checkField(t, t.getAttribute("aria-invalid") === "true");
  });
  document.addEventListener("invalid", function (e) {
    var t = e.target;
    if (t instanceof Element && t.matches("[data-msg]")) checkField(t, true);
  }, true);

  // ---- ui.FileInto: read a small text file into a textarea ----
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!(t instanceof Element) || !t.matches("[data-file-into]") || !t.files || !t.files[0]) return;
    var target = document.getElementById(t.getAttribute("data-file-into"));
    var status = t.closest("[data-file-tools]") && t.closest("[data-file-tools]").querySelector("[data-file-status]");
    var file = t.files[0];
    if (!target || file.size > 256 * 1024) {
      if (status) status.textContent = "Dosya okunamadı (en fazla 256 KB).";
      return;
    }
    file.text().then(function (text) {
      target.value = text;
      target.dispatchEvent(new Event("input", { bubbles: true }));
      if (status) status.textContent = file.name + " yüklendi.";
    }, function () { if (status) status.textContent = "Dosya okunamadı."; });
    t.value = "";
  });

  // ---- ui.ListTable: sort and search in the browser ----
  var collator = new Intl.Collator("tr", { numeric: true, sensitivity: "base" });
  var NUM = /^-?\d+(?:[.,]\d+)?$/;

  function cellKey(row, i) {
    var c = row.cells[i];
    if (!c) return "";
    var k = c.getAttribute("data-sort");
    return (k !== null ? k : c.textContent).replace(/\s+/g, " ").trim();
  }
  function compare(a, b) {
    if (a === b) return 0;
    if (a === "") return 1; // empty values last in both directions
    if (b === "") return -1;
    if (NUM.test(a) && NUM.test(b)) return parseFloat(a.replace(",", ".")) - parseFloat(b.replace(",", "."));
    return collator.compare(a, b);
  }
  // A data row is one whose cells line up with the header; a single spanning cell (a note) is not.
  function dataRows(tbody) {
    return Array.prototype.filter.call(tbody.rows, function (r) {
      return !(r.cells.length === 1 && r.cells[0].colSpan > 1);
    });
  }
  // A polled list (htmx outerHTML swap) comes back unsorted and unfiltered; the last sort and search
  // of each table are kept by its label and applied again to the new rows.
  var kept = Object.create(null);
  function keyOf(table) { return table.getAttribute("aria-label") || ""; }
  function sortBy(th, forced) {
    var table = th.closest("table");
    var tbody = table && table.tBodies[0];
    if (!tbody) return;
    var dir = forced || (th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending");
    var k = keyOf(table);
    kept[k] = kept[k] || {};
    kept[k].col = th.cellIndex;
    kept[k].dir = dir;
    table.querySelectorAll("thead th[aria-sort]").forEach(function (h) { h.removeAttribute("aria-sort"); });
    th.setAttribute("aria-sort", dir);
    var i = th.cellIndex, sign = dir === "ascending" ? 1 : -1;
    var rows = dataRows(tbody);
    var keyed = rows.map(function (r, n) { return { r: r, k: cellKey(r, i), n: n }; });
    keyed.sort(function (x, y) {
      var c = compare(x.k, y.k);
      if (x.k === "" || y.k === "") return c; // empties stay last
      return c * sign || x.n - y.n;
    });
    keyed.forEach(function (x) { tbody.appendChild(x.r); });
  }
  function enhanceTable(table) {
    var head = table.tHead && table.tHead.rows[table.tHead.rows.length - 1];
    if (!head) return;
    Array.prototype.forEach.call(head.cells, function (th) {
      if (th.hasAttribute("data-nosort") || th.colSpan > 1 || th.textContent.trim() === "") return;
      var b = document.createElement("button");
      b.type = "button";
      b.className = "th-sort";
      while (th.firstChild) b.appendChild(th.firstChild);
      th.appendChild(b);
    });
  }
  function filter(box) {
    var input = box.querySelector("[data-table-search]");
    var table = box.querySelector("table");
    if (!input || !table || !table.tBodies[0]) return;
    var k = keyOf(table);
    kept[k] = kept[k] || {};
    kept[k].q = input.value;
    var q = input.value.toLocaleLowerCase("tr").trim();
    var rows = dataRows(table.tBodies[0]), shown = 0;
    rows.forEach(function (r) {
      var hit = q === "" || r.textContent.toLocaleLowerCase("tr").indexOf(q) !== -1;
      r.hidden = !hit;
      if (hit) shown++;
    });
    var count = box.querySelector("[data-table-count]");
    if (count) count.textContent = q === "" ? rows.length + " satır" : shown + " / " + rows.length + " satır";
    var none = box.querySelector("[data-table-none]");
    if (none) none.hidden = shown !== 0 || rows.length === 0;
  }
  function enhance(scope) {
    var all = function (sel) {
      var list = Array.prototype.slice.call(scope.querySelectorAll(sel));
      if (scope.matches && scope.matches(sel)) list.unshift(scope);
      return list;
    };
    all("dialog[data-dialog-auto-open]").forEach(function (dialog) {
      if (!dialog.showModal) return;
      if (!dialog.open) dialog.showModal();
      dialog.removeAttribute("data-dialog-auto-open");
      var invalid = dialog.querySelector('[aria-invalid="true"]');
      if (invalid) invalid.focus();
    });
    all("[data-multi]").forEach(enhanceMulti);
    all("[data-file-tools]").forEach(function (box) { box.hidden = false; });
    all("[data-line-pattern]").forEach(function (el) { checkField(el, false); });
    all("details.menu").forEach(function (menu) {
      var list = menu.querySelector(".menu-list");
      if (!list || !list.showPopover || list.hasAttribute("popover")) return;
      list.setAttribute("popover", "manual");
      menu.querySelector("summary").setAttribute("aria-expanded", "false");
    });
    all("table[data-sortable]").forEach(function (table) {
      if (table.hasAttribute("data-enhanced")) return;
      table.setAttribute("data-enhanced", "");
      enhanceTable(table);
      var st = kept[keyOf(table)];
      var head = table.tHead && table.tHead.rows[table.tHead.rows.length - 1];
      if (st && st.dir && head && head.cells[st.col] && head.cells[st.col].querySelector(".th-sort")) {
        sortBy(head.cells[st.col], st.dir);
      }
    });
    all("[data-table]").forEach(function (box) {
      var tools = box.querySelector("[data-table-tools]");
      if (!tools) return;
      tools.hidden = false;
      var table = box.querySelector("table");
      var st = table && kept[keyOf(table)];
      var input = box.querySelector("[data-table-search]");
      if (st && st.q && input && input.value === "") input.value = st.q;
      filter(box);
    });
  }
  // Save interaction state immediately before replacement, not at request start: the person may
  // keep typing while a polling request is in flight.
  document.addEventListener("htmx:beforeSwap", function (e) {
    var target = e.detail && e.detail.target;
    if (!(target instanceof Element)) return;
    var boxes = Array.prototype.slice.call(target.querySelectorAll("[data-table]"));
    if (target.matches("[data-table]")) boxes.unshift(target);
    boxes.forEach(function (box) {
      var table = box.querySelector("table");
      if (!table) return;
      var st = kept[keyOf(table)] || (kept[keyOf(table)] = {});
      var scroll = box.querySelector(".tscroll");
      st.scroll = scroll ? scroll.scrollLeft : 0;
      st.focus = null;
      var active = document.activeElement;
      if (!active || !box.contains(active)) return;
      if (active.matches("[data-table-search]")) {
        st.q = active.value;
        st.focus = { search: true, start: active.selectionStart, end: active.selectionEnd };
      } else if (active.matches(".th-sort")) {
        st.focus = { col: active.closest("th").cellIndex };
      } else if (active.matches("a[href]")) {
        st.focus = { href: active.getAttribute("href") };
      }
    });
  });
  document.addEventListener("htmx:afterSwap", function (e) {
    // For outerHTML swaps eventInfo.target may be detached; the event is sent on the new node.
    var target = e.target;
    if (!(target instanceof Element)) return;
    enhance(target);
    var boxes = Array.prototype.slice.call(target.querySelectorAll("[data-table]"));
    if (target.matches("[data-table]")) boxes.unshift(target);
    boxes.forEach(function (box) {
      var table = box.querySelector("table");
      var st = table && kept[keyOf(table)];
      if (!st) return;
      var scroll = box.querySelector(".tscroll");
      if (scroll) scroll.scrollLeft = st.scroll || 0;
      if (st.focus && (!document.activeElement || document.activeElement === document.body || !document.activeElement.isConnected || box.contains(document.activeElement))) {
        var head = table.tHead && table.tHead.rows[table.tHead.rows.length - 1];
        var cell = head && head.cells[st.focus.col];
        var focus = st.focus.search ? box.querySelector("[data-table-search]") : cell && cell.querySelector(".th-sort");
        if (st.focus.href) {
          focus = Array.prototype.find.call(box.querySelectorAll("a[href]"), function (link) {
            return link.getAttribute("href") === st.focus.href && !link.closest("[hidden]");
          });
        }
        if (focus) {
          focus.focus({ preventScroll: true });
          if (st.focus.search && st.focus.start !== null) focus.setSelectionRange(st.focus.start, st.focus.end);
        }
      }
      st.focus = null;
    });
  });
  document.addEventListener("htmx:load", function (e) {
    if (e.target instanceof Element) enhance(e.target);
  });
  document.addEventListener("input", function (e) {
    var t = e.target;
    if (t instanceof Element && t.matches("[data-table-search]")) filter(t.closest("[data-table]"));
  });
  // ---- ui.Textarea{Editor}: the code editor is a separate, larger file, fetched only when needed ----
  function loadEditor() {
    if (!document.querySelector("textarea[data-code-editor]") || document.getElementById("code-editor-js")) return;
    var s = document.createElement("script");
    s.id = "code-editor-js";
    s.src = "/static/editor.js";
    document.head.appendChild(s);
  }
  function ready() {
    enhance(document);
    loadEditor();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready);
  else ready();
})();
