/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_base", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone"], function(e, t, n, i, a) {
    return function(e) {
        function t(i) {
            if (n[i]) return n[i].exports;
            var a = n[i] = {
                exports: {},
                id: i,
                loaded: !1
            };
            return e[i].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        e.exports = n(1)
    }, function(e, t, n) {
        var i, a;
        i = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, i, a, o) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var i = e.extend.call(this, t, n);
                    if (i.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) i.prototype.defaults[a] || (i.prototype.defaults[a] = this.prototype.defaults[a]);
                    return i
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: o.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: o.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = i(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    i(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            o = a.entry[0].content.search;
                        i(t).val(o), i(t).data("evt_name", e.get("base_eventtype"))
                    }), i("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = i(t).data();
                        e._update_eventtype(a.evt_name, i(t).val())
                    }), i("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, i.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    i(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), i("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), i(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, i.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        i = e.t;
                    i.service.request(i._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(i.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        t[i] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(o), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = i("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        o = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? i("#" + this.get("tab_content_id")).prepend(s) : i("#" + this.get("button_container")).append(s), i("#" + n).on("click", function(e) {
                        a.each(o.get("modal_defaults"), function(e, t) {
                            o._set_modal_default(o.get("modal_id"), t, e)
                        }), i("#" + o.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    i(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    i("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return i("#" + this.get("tab_content_container")).append(n), i("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), i(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), i(this).css("class", "active");
                        var n = i(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), i(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    i("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        o = e.create_item(t);
                    i(n).append(o.html), i("#" + o.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), i("#" + o.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: o.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: o.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: o.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        i("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    i("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        i = e >= 60;
                    return t || n || i
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data(),
                        o = a.disabled,
                        s = !o,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        d = a.edit_link,
                        c = e.get("msg_box");
                    e.service.request(d, "POST", null, null, i.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(o) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            i(t).css("color", r), i(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), i("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(c, "Disabled: " + s), i("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        d = !1;
                    o.includes("[]") && (l = [], i(i("#" + s + '_configuration input:checkbox:checked[name="' + o + '"]')).each(function(e) {
                        l[e] = i(this).val()
                    }), i("#" + s + '_configuration input[id="' + o.replace("[]", "") + '"]').each(function(e) {
                        var t = i(this).val();
                        t.length > 1 && (l[l.length] = i(this).val())
                    }), l = l.join(","), r = o.replace("[]", ""), d = !0);
                    var c = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (i(c).length > 0 && !d) {
                        var _ = [];
                        i(i("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            _[e] = i(this).val()
                        }), _[_.length] = l, l = _.join(","), d = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, i.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, i) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = a.id,
                        s = n[0].id,
                        r = i("#" + o + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var d = l.v;
                    if ("must_have" in a && (s = a.must_have, d = i("#" + o + '_configuration input[id="' + a.must_have + '"]').val()), d = d.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (d = n.is(":checked") ? "true" : "false"), e._validate_object(s, d)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: o,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            }), e.update_property({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            })
                    } else e.display_error(o + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        o = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = i.param({
                            value: o
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        o = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: o.guid()
                            })
                        }
                        var l = i("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + "_list_indexes");
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_config", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, i, a, o) {
    return function(e) {
        function t(i) {
            if (n[i]) return n[i].exports;
            var a = n[i] = {
                exports: {},
                id: i,
                loaded: !1
            };
            return e[i].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var i, a;
        i = [n(2), n(1), n(3), n(4), n(5), n(10)], a = function(e, t, i, a, o, s) {
            return t.fullExtend({
                defaults: {
                    msg_box: "app_config_error_msg"
                },
                initialize: function() {
                    this.constructor.__super__.initialize.apply(this, arguments), this.$el = i(this.el), this.set({
                        _template_tab_content: n(11)
                    }), this.set({
                        tab_content_id: this.add_tab({
                            text: "Application Configuration",
                            tab_content: this.get("_template_tab_content")
                        })
                    }), i(".toggle-tab").first().css("class", "active");
                    var e = this;
                    i("#app_config_button").on("click", function() {
                        e._save_app_configuration(e)
                    })
                },
                _save_app_configuration: function(e) {
                    var t = {
                            configured: "true"
                        },
                        n = i.param(t);
                    e.service.request(e._build_service_url("apps/local/%app%"), "POST", null, null, n, {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        e._reload_app_config(e, t)
                    })
                },
                _reload_app_config: function(e, t) {
                    t = JSON.parse(t), e.service.request(e._build_service_url("apps/local/_reload"), "GET").error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        e._show_message("Application Configuration Saved")
                    })
                },
                _show_message: function(e) {
                    this.display_message(this.get("msg_box"), e)
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(e, t, n) {
        var i, a;
        i = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, i, a, o) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var i = e.extend.call(this, t, n);
                    if (i.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) i.prototype.defaults[a] || (i.prototype.defaults[a] = this.prototype.defaults[a]);
                    return i
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: o.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: o.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = i(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    i(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            o = a.entry[0].content.search;
                        i(t).val(o), i(t).data("evt_name", e.get("base_eventtype"))
                    }), i("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = i(t).data();
                        e._update_eventtype(a.evt_name, i(t).val())
                    }), i("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, i.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    i(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), i("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), i(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, i.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        i = e.t;
                    i.service.request(i._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(i.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        t[i] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(o), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = i("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        o = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? i("#" + this.get("tab_content_id")).prepend(s) : i("#" + this.get("button_container")).append(s), i("#" + n).on("click", function(e) {
                        a.each(o.get("modal_defaults"), function(e, t) {
                            o._set_modal_default(o.get("modal_id"), t, e)
                        }), i("#" + o.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    i(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    i("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return i("#" + this.get("tab_content_container")).append(n), i("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), i(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), i(this).css("class", "active");
                        var n = i(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), i(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    i("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        o = e.create_item(t);
                    i(n).append(o.html), i("#" + o.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), i("#" + o.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: o.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: o.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: o.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        i("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    i("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        i = e >= 60;
                    return t || n || i
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data(),
                        o = a.disabled,
                        s = !o,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        c = a.edit_link,
                        d = e.get("msg_box");
                    e.service.request(c, "POST", null, null, i.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(o) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            i(t).css("color", r), i(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), i("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(d, "Disabled: " + s), i("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        c = !1;
                    o.includes("[]") && (l = [], i(i("#" + s + '_configuration input:checkbox:checked[name="' + o + '"]')).each(function(e) {
                        l[e] = i(this).val()
                    }), i("#" + s + '_configuration input[id="' + o.replace("[]", "") + '"]').each(function(e) {
                        var t = i(this).val();
                        t.length > 1 && (l[l.length] = i(this).val())
                    }), l = l.join(","), r = o.replace("[]", ""), c = !0);
                    var d = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (i(d).length > 0 && !c) {
                        var _ = [];
                        i(i("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            _[e] = i(this).val()
                        }), _[_.length] = l, l = _.join(","), c = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, i.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, i) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = a.id,
                        s = n[0].id,
                        r = i("#" + o + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var c = l.v;
                    if ("must_have" in a && (s = a.must_have, c = i("#" + o + '_configuration input[id="' + a.must_have + '"]').val()), c = c.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (c = n.is(":checked") ? "true" : "false"), e._validate_object(s, c)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: o,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: c
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: c
                            }), e.update_property({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: c
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: c
                            })
                    } else e.display_error(o + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        o = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = i.param({
                            value: o
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        o = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: o.guid()
                            })
                        }
                        var l = i("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + "_list_indexes");
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = o
    }, function(e, t) {
       e.exports = '<h3>Application Configuration</h3>\n<div id="app_config_error_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"/>\n<div id="app_config_modify_container"  class="controls controls-fill existing_container"/>\n'
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_credential", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, i, a, o) {
    return function(e) {
        function t(i) {
            if (n[i]) return n[i].exports;
            var a = n[i] = {
                exports: {},
                id: i,
                loaded: !1
            };
            return e[i].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var i, a;
        i = [n(2), n(1), n(3), n(4), n(5), n(10)], a = function(e, t, i, a, o, s) {
            return t.fullExtend({
                defaults: {},
                initialize: function() {
                    this.constructor.__super__.initialize.apply(this, arguments), this.$el = i(this.el);
                    var e = this;
                    this.set({
                        _template_form_modal: n(12),
                        _template_form_item: n(13)
                    }), this._generate_modal({
                        modal_id: e.get("modal_id"),
                        is_input: e.get("is_input"),
                        modal_name: "Create New Credential",
                        modal_form_html: e.get("_template_form_modal"),
                        on_submit: e._submit_new_credential,
                        that: e
                    }), this.set({
                        tab_content_id: this.add_tab({
                            text: "Credentials",
                            tab_xref: "credentials"
                        })
                    }), this._setup_button(), this._load_existing_credentials(), this._set_documentation("Credentials", "The <b>Create New Credential</b> button, and corresponding <b>Credentials</b> tab allow interactions with Splunk's Encrypted Credential Store.")
                },
                _load_existing_credentials: function() {
                    var e = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").done(function(t) {
                        e._parse_item(e, t)
                    }).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    })
                },
                _parse_item: function(e, t) {
                    t = JSON.parse(t);
                    for (var n = 0; n < t.entry.length; n++) {
                        var i = t.entry[n],
                            a = /^[^\\\/!@#$%\^&\*\(\):\s]*$/i,
                            o = {
                                item_form: e.get("_template_form_item"),
                                is_input: e.get("is_input"),
                                item_disabled_state: !1,
                                enable_reload: !1,
                                item_name: i.content.realm,
                                data_options: [{
                                    id: "remove_link",
                                    value: i.links.remove
                                }, {
                                    id: "stanza_name",
                                    value: i.name
                                }],
                                items: {
                                    username: null === i.content.username.match(a) ? decodeURIComponent(i.content.username) : i.content.username,
                                    password: Array(i.content.password.length).join("*")
                                }
                            };
                        e._display_item(e, o)
                    }
                },
                _submit_new_credential: function(e, t) {
                    var n = e.prep_data(i(t).serializeArray());
                    return !!e._validate_data(n) && (e.reset_message(e.get("modal_id") + "_msg_box"), void e.create_credential({
                        user: n.user,
                        password: n.password,
                        realm: n.realm || e.get("app"),
                        error: e._generic_error_request,
                        done: function(t) {
                            e._parse_item(e, t), e.display_message(e.get("modal_id") + "_msg_box", "Credential Configuration Added"), i('form[name="' + e.get("modal_id") + '_new_configuration"').trigger("reset")
                        }
                    }))
                },
                _validate_data: function(e) {
                    return e.user.length < 1 ? (this.display_error(this.get("modal_id") + "_msg_box", "Username is required"), !1) : e.password.length < 1 ? (this.display_error(this.get("modal_id") + "_msg_box", "Password is required"), !1) : e
                },
                _setup_button: function() {
                    this.set({
                        button_id: this.add_button("Create New Credential", !0)
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(e, t, n) {
        var i, a;
        i = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, i, a, o) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var i = e.extend.call(this, t, n);
                    if (i.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) i.prototype.defaults[a] || (i.prototype.defaults[a] = this.prototype.defaults[a]);
                    return i
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: o.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: o.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = i(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    i(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            o = a.entry[0].content.search;
                        i(t).val(o), i(t).data("evt_name", e.get("base_eventtype"))
                    }), i("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = i(t).data();
                        e._update_eventtype(a.evt_name, i(t).val())
                    }), i("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, i.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    i(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), i("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), i(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, i.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        i = e.t;
                    i.service.request(i._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(i.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        t[i] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(o), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = i("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        o = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? i("#" + this.get("tab_content_id")).prepend(s) : i("#" + this.get("button_container")).append(s), i("#" + n).on("click", function(e) {
                        a.each(o.get("modal_defaults"), function(e, t) {
                            o._set_modal_default(o.get("modal_id"), t, e)
                        }), i("#" + o.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    i(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    i("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return i("#" + this.get("tab_content_container")).append(n), i("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), i(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), i(this).css("class", "active");
                        var n = i(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), i(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    i("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        o = e.create_item(t);
                    i(n).append(o.html), i("#" + o.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), i("#" + o.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: o.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: o.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: o.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        i("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    i("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        i = e >= 60;
                    return t || n || i
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data(),
                        o = a.disabled,
                        s = !o,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        d = a.edit_link,
                        c = e.get("msg_box");
                    e.service.request(d, "POST", null, null, i.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(o) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            i(t).css("color", r), i(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), i("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(c, "Disabled: " + s), i("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        d = !1;
                    o.includes("[]") && (l = [], i(i("#" + s + '_configuration input:checkbox:checked[name="' + o + '"]')).each(function(e) {
                        l[e] = i(this).val()
                    }), i("#" + s + '_configuration input[id="' + o.replace("[]", "") + '"]').each(function(e) {
                        var t = i(this).val();
                        t.length > 1 && (l[l.length] = i(this).val())
                    }), l = l.join(","), r = o.replace("[]", ""), d = !0);
                    var c = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (i(c).length > 0 && !d) {
                        var _ = [];
                        i(i("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            _[e] = i(this).val()
                        }), _[_.length] = l, l = _.join(","), d = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, i.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, i) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = a.id,
                        s = n[0].id,
                        r = i("#" + o + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var d = l.v;
                    if ("must_have" in a && (s = a.must_have, d = i("#" + o + '_configuration input[id="' + a.must_have + '"]').val()), d = d.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (d = n.is(":checked") ? "true" : "false"), e._validate_object(s, d)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: o,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            }), e.update_property({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            })
                    } else e.display_error(o + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        o = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = i.param({
                            value: o
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        o = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: o.guid()
                            })
                        }
                        var l = i("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + "_list_indexes");
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = o
    }, , function(e, t) {
        e.exports = '<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Username</label>\n    <div class="controls controls-block">\n        <input type="text" id="user" name="user" required="required"/>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Password</label>\n    <div class="controls controls-block">\n        <input type="password" id="password" name="password" required="required"/>\n        <span class="help-block "></span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Realm</label>\n    <div class="controls controls-block">\n        <input type="text" id="realm" name="realm"/>\n        <span class="help-block">Optional. If not specified, will use the App Context.</span>\n    </div>\n</div>\n'
    }, function(e, t) {
        e.exports = '<div class="controls controls-fill">\n    <label class="control-label">Username:</label>\n    <input type="text" class="input-medium username" id="{{item_id}}_modify_username" value="{{items.username}}"\n           disabled="disabled"/>\n</div>\n<div class="controls controls-fill">\n    <label class="control-label">Password:</label>\n    <input type="password" class="input-medium password" id="{{item_id}}_modify_password" value="{{items.password}}"\n           disabled="disabled"/>\n</div> '
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_mi_ga", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, i, a, o) {
    return function(e) {
        function t(i) {
            if (n[i]) return n[i].exports;
            var a = n[i] = {
                exports: {},
                id: i,
                loaded: !1
            };
            return e[i].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var i, a;
        i = [n(2), n(1), n(3), n(4), n(5), n(10)], a = function(e, t, i, a, o, s) {
            return t.fullExtend({
                defaults: {
                    mi_name: "ga",
                    mi_text: "G Suite",
                    base_eventtype: "googleapps",
                    is_input: !0,
                    supports_proxy: !0,
                    supports_credential: !0,
                    ga_services: [{
                        title: "Activity - All",
                        id: "report:all"
                    }, {
                        title: "Activity - Admin",
                        id: "report:admin"
                    }, {
                        title: "Activity - Calendar",
                        id: "report:calendar"
                    }, {
                        title: "Activity - Drive",
                        id: "report:drive"
                    }, {
                        title: "Activity - Token",
                        id: "report:token"
                    }, {
                        title: "Activity - Mobile",
                        id: "report:mobile"
                    }, {
                        title: "Activity - Groups",
                        id: "report:groups"
                    }, {
                        title: "Activity - Login",
                        id: "report:login"
                    }, {
                        title: "Activity - Rules",
                        id: "report:rules"
                    }, {
                        title: "Activity - Chat",
                        id: "report:chat"
                    }, {
                        title: "Activity - SAML",
                        id: "report:saml"
                    }, {
                        title: "Activity - GPlus",
                        id: "report:gplus"
                    }, {
                        title: "Chrome OS Devices",
                        id: "usage:chrome"
                    }, {
                        title: "Google Analytics - Report",
                        id: "analytics:report"
                    }, {
                        title: "Google Analytics - Metadata",
                        id: "analytics:metdata"
                    }, {
                        title: "Usage - User",
                        id: "usage:user"
                    }, {
                        title: "Usage - Customer",
                        id: "usage:customer"
                    }],
                    ga_service_ids: []
                },
                initialize: function() {
                    this.constructor.__super__.initialize.apply(this, arguments), this.$el = i(this.el);
                    var e = this;
                    a.each(this.get("ga_services"), function(t) {
                        e.get("ga_service_ids").push(t.id)
                    }), this.set({
                        _template_form_modal: n(14)("./asa_" + this.get("mi_name") + "_model.html"),
                        _template_form_item: n(16)("./asa_" + this.get("mi_name") + "_item.html")
/*                    }), this._generate_modal({
                        modal_name: "Create New " + e.get("mi_text") + " Input",
                        modal_form_html: e.get("_template_form_modal"),
                        on_submit: e._submit_new_input,
                        ga_services: e.get("ga_services"),
                        that: e,
                        test_class: "modular_input_save_button" */
                    }), this._input_spec_exists(e, this.get("mi_name"), function(e) {
                        e._setup_button(), e.set({
                            tab_content_id: e.add_tab({
                                text: e.get("mi_text"),
                                tab_xref: e.get("mi_name")
                            })
                        }), e._load_existing_inputs()
                    })
                },
                _load_existing_inputs: function() {
                    var e = this;
                    this.service.request(this._build_service_url("configs/conf-inputs"), "GET", {
                        search: this.get("mi_name") + ":"
                    }).done(function(t) {
                        e._parse_item(e, t)
                    }).error(e._generic_error_request)
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "extraconfig":
                            try {
                                return t = JSON.parse(t), "object" == typeof t
                            } catch (e) {
                                return console.log({
                                    error: e
                                }), !1
                            }
                        case "proxy_name":
                            return this._validate_proxy_name(t);
                        case "interval":
                            return this._validate_interval(t);
                        case "mod_input_name":
                            return this._validate_mod_input_name(t);
                        case "servicename":
                            var n = t.indexOf(",") >= 0 ? t.split(",") : [t],
                                i = !0,
                                o = this.get("ga_service_ids");
                            return a.each(n, function(e) {
                                if (o.indexOf(e) < 0) return !1
                            }), i;
                        default:
                            return !0
                    }
                },
                _parse_item: function(e, t) {
                    t = JSON.parse(t);
                    for (var n = 0; n < t.entry.length; n++) {
                        var i, a = t.entry[n],
                            o = [],
                            s = [];
                        if (a.content.hasOwnProperty("servicename")) {
                            i = a.content.servicename.indexOf(",") >= 0 ? a.content.servicename.split(",") : [a.content.servicename];
                            for (var r = 0; r < i.length; r++) e.get("ga_service_ids").indexOf(i[r]) >= 0 && s.push(i[r])
                        }
                        for (var l = 0; l < e.get("ga_services").length; l++) {
                            var d = e.get("ga_services")[l],
                                c = {
                                    id: d.id,
                                    title: d.title,
                                    checked: ""
                                };
                            a.content.hasOwnProperty("servicename") && s.indexOf(d.id) >= 0 && (c.checked = ' checked="checked" '), o.push(c)
                        }
                        var _ = {
                            item_form: e.get("_template_form_item"),
                            item_disabled_state: a.content.disabled,
                            enable_reload: !0,
                            item_name: a.name,
                            mi_name: e.get("mi_name"),
                            supports_credential: e.get("supports_credential"),
                            data_options: [{
                                id: "edit_link",
                                value: a.links.edit
                            }, {
                                id: "remove_link",
                                value: a.links.remove
                            }, {
                                id: "stanza_name",
                                value: a.name
                            }, {
                                id: "disabled",
                                value: a.content.disabled
                            }, {
                                id: "mi_name",
                                value: e.get("mi_name")
                            }],
                            items: {
                                domain: a.content.domain,
                                interval: a.content.interval,
                                servicename: o,
                                extraconfig: a.content.hasOwnProperty("extraconfig") ? JSON.stringify(JSON.parse(a.content.extraconfig.toString())).replace(/\"/g, "&quot;") : "",
                                proxy_name: a.content.hasOwnProperty("proxy_name") ? a.content.proxy_name : "not_configured",
                                index: a.content.hasOwnProperty("index") ? a.content.index : ""
                            }
                        };
                        e._display_item(e, _)
                    }
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        if (i.indexOf("[]") >= 0) {
                            var o = i.replace("[]", "");
                            t.hasOwnProperty(o) || (t[o] = []), t[o].push(a)
                        } else t[i] = a
                    }
                    return t
                },
                _submit_new_input: function(e, t) {
                    var n = e.prep_data(i(t).serializeArray());
                    return !!e._validate_data(e, n) && (e.reset_message(e.get("modal_id") + "_msg_box"), n.disabled = "false", void e._create_item(e, {
                        endpoint: "configs/conf-inputs",
                        data: n,
                        done: function(e, t) {
                            e._parse_item(e, t), e.display_message(e.get("modal_id") + "_msg_box", e.get("mi_text") + " Input Configuration Added"), i('form[name="' + e.get("modal_id") + '_configuration"]').trigger("reset")
                        }
                    }))
                },
                _validate_data: function(e, t) {
                    if (t.servicename = e._combine_multibox(e, i("#" + e.get("modal_id") + ' input[name="servicename[]"]').first()).v, !e._validate_object("mod_input_name", t.mod_input_name)) return e.display_error(e.get("modal_id") + "_msg_box", "Name is required, and must not contain special characters."), !1;
                    if (t.name = e.get("mi_name") + "://" + t.mod_input_name, delete t.mod_input_name, !e._validate_object("interval", t.interval)) return e.display_error(e.get("modal_id") + "_msg_box", "Interval is required, and can only be numbers, and must be more than 60."), !1;
                    if (!e._validate_object("domain", t.domain)) return e.display_error(e.get("modal_id") + "_msg_box", "Domain is required"), !1;
                    if (!e._validate_object("servicename", t.servicename)) return e.display_error(e.get("modal_id") + "_msg_box", "Service Name is required"), !1;
                    if (!e._validate_object("extraconfig", t.extraconfig)) return e.display_error(e.get("modal_id") + "_msg_box", "Extra Config must be valid JSON."), !1;
                    if (t.index.length < 1) delete t.index;
                    else if (!e._validate_object("index", t.index)) return e.display_error(e.get("modal_id") + "_msg_box", "Index must be present."), !1;
                    return t.proxy_name.length < 1 && delete t.proxy_name, t
/*                },
                _setup_button: function() {
                    this.set({
                        button_id: this.add_button("Create New " + this.get("mi_text") + " Input")
                    })  */
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(e, t, n) {
        var i, a;
        i = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, i, a, o) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var i = e.extend.call(this, t, n);
                    if (i.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) i.prototype.defaults[a] || (i.prototype.defaults[a] = this.prototype.defaults[a]);
                    return i
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: o.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: o.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = i(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    i(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            o = a.entry[0].content.search;
                        i(t).val(o), i(t).data("evt_name", e.get("base_eventtype"))
                    }), i("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = i(t).data();
                        e._update_eventtype(a.evt_name, i(t).val())
                    }), i("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, i.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    i(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), i("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), i(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, i.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        i = e.t;
                    i.service.request(i._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(i.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        t[i] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(o), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = i("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        o = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? i("#" + this.get("tab_content_id")).prepend(s) : i("#" + this.get("button_container")).append(s), i("#" + n).on("click", function(e) {
                        a.each(o.get("modal_defaults"), function(e, t) {
                            o._set_modal_default(o.get("modal_id"), t, e)
                        }), i("#" + o.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    i(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    i("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return i("#" + this.get("tab_content_container")).append(n), i("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), i(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), i(this).css("class", "active");
                        var n = i(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), i(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    i("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        o = e.create_item(t);
                    i(n).append(o.html), i("#" + o.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), i("#" + o.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: o.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: o.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: o.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        i("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    i("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        i = e >= 60;
                    return t || n || i
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data(),
                        o = a.disabled,
                        s = !o,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        d = a.edit_link,
                        c = e.get("msg_box");
                    e.service.request(d, "POST", null, null, i.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(o) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            i(t).css("color", r), i(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), i("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(c, "Disabled: " + s), i("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        d = !1;
                    o.includes("[]") && (l = [], i(i("#" + s + '_configuration input:checkbox:checked[name="' + o + '"]')).each(function(e) {
                        l[e] = i(this).val()
                    }), i("#" + s + '_configuration input[id="' + o.replace("[]", "") + '"]').each(function(e) {
                        var t = i(this).val();
                        t.length > 1 && (l[l.length] = i(this).val())
                    }), l = l.join(","), r = o.replace("[]", ""), d = !0);
                    var c = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (i(c).length > 0 && !d) {
                        var _ = [];
                        i(i("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            _[e] = i(this).val()
                        }), _[_.length] = l, l = _.join(","), d = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, i.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, i) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = a.id,
                        s = n[0].id,
                        r = i("#" + o + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var d = l.v;
                    if ("must_have" in a && (s = a.must_have, d = i("#" + o + '_configuration input[id="' + a.must_have + '"]').val()), d = d.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (d = n.is(":checked") ? "true" : "false"), e._validate_object(s, d)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: o,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            }), e.update_property({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            })
                    } else e.display_error(o + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        o = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = i.param({
                            value: o
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        o = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: o.guid()
                            })
                        }
                        var l = i("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + "_list_indexes");
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = o
    }, , , , function(e, t, n) {
        function i(e) {
            return n(a(e))
        }

        function a(e) {
            return o[e] || function() {
                throw new Error("Cannot find module '" + e + "'.")
            }()
        }
        var o = {
            "./asa_ga_model.html": 15
        };
        i.keys = function() {
            return Object.keys(o)
        }, i.resolve = a, e.exports = i, i.id = 14
    }, function(e, t) {
        e.exports = '<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Modular Input Name</label>\n    <div class="controls controls-block">\n        <input data-id="{{modal_id}}" type="text" id="mod_input_name" name="mod_input_name" required="required"/>\n\n        <span class="help-block ">Required. A unique identifier. Can only contain letters, numbers and underscores.</span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Domain</label>\n    <div class="controls controls-block">\n        <input data-id="{{modal_id}}" type="text" id="domain" name="domain" required="required"/>\n        <span class="help-block ">Required. This is the domain (TLD) to use. Example: splunk.com</span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Services</label><br/>\n    <span class="help-block ">The services to Collect.</span>\n    <% _.each( ga_services, function (r) { %>\n    <div class="controls controls-block" style="text-align:right; ">\n        <span class="control-label" style="text-align:right; width:75%; height:50px; float:none; margin-right:25px; ">{{r.title}}</span>\n        <input data-id="{{modal_id}}" type="checkbox" class="report_checkbox" id="servicename_{{r.id}}"\n               name="servicename[]" value="{{r.id}}"/>\n    </div>\n    <% }); %>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Extra Config</label>\n    <div class="controls controls-block">\n        <input data-id="{{modal_id}}" type="text" id="extraconfig" name="extraconfig" required="required"/>\n        <span class="help-block ">Required. A valid JSON object to help advanced configurations. {} is ok if no options.</span>\n    </div>\n</div>'
    }, function(e, t, n) {
        function i(e) {
            return n(a(e))
        }

        function a(e) {
            return o[e] || function() {
                throw new Error("Cannot find module '" + e + "'.")
            }()
        }
        var o = {
            "./asa_ga_item.html": 17
        };
        i.keys = function() {
            return Object.keys(o)
        }, i.resolve = a, e.exports = i, i.id = 16
    }, function(e, t) {
        e.exports = '<div class="controls controls-fill">\n    <label class="control-label">Domain</label>\n    <input type="text" oninput="this.title = this.value" title="{{items.domain}}"\n           class="input-medium domain"\n           data-id="{{item_id}}" id="domain" name="domain"\n           value="{{items.domain}}"/>\n</div>\n<div class="controls controls-fill">\n    <label class="control-label">Services</label>\n    <% _.each( items.servicename, function (r) { %>\n    <div class="controls controls-block" style="text-align:right; width:250px;">\n        <span class="control-label" style="text-align:right; float:none; margin-right:25px; ">{{r.title}}</span>\n        <input type="checkbox" class="report_checkbox" data-id="{{item_id}}" id="servicename_{{r.id}}"\n               name="servicename[]" {{r.checked}} value="{{r.id}}"/>\n    </div>\n    <% }); %>\n</div>\n<div class="controls controls-fill">\n    <label class="control-label">Extra Configuration:</label>\n    <input type="text" oninput="this.title = this.value" title="{{items.extraconfig}}"\n           class="input-medium credential_realm"\n           data-id="{{item_id}}" id="extraconfig" name="extraconfig"\n           value="{{items.extraconfig}}"/>\n</div>'
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_proxy", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, o, a, i) {
    return function(e) {
        function t(o) {
            if (n[o]) return n[o].exports;
            var a = n[o] = {
                exports: {},
                id: o,
                loaded: !1
            };
            return e[o].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var o, a;
        o = [n(2), n(1), n(3), n(4), n(5), n(10)], a = function(e, t, o, a, i, s) {
            return t.fullExtend({
                defaults: {},
                initialize: function() {
                    this.constructor.__super__.initialize.apply(this, arguments), this.$el = o(this.el);
                    var e = this;
                    this.set({
                        _template_form_modal: n(18),
                        _template_form_item: n(19)
                    }), this._generate_modal({
                        modal_id: e.get("modal_id"),
                        modal_name: "Create New Proxy",
                        is_input: e.get("is_input"),
                        modal_form_html: e.get("_template_form_modal"),
                        on_submit: e._submit_new_proxy,
                        that: e
                    }), this.set({
                        tab_content_id: this.add_tab({
                            text: "Proxy Configurations",
                            tab_xref: "proxies"
                        })
                    }), this._setup_button(), this._load_existing_proxies(), this._set_documentation("Proxy", "The <b>Create New Proxy</b> button, and corresponding <b>Proxy Configurations</b> tab assists in configuring proxy settings for any available and supported Modular Inputs.")
                },
                _load_existing_proxies: function() {
                    var e = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").done(function(t) {
                        e._parse_item(e, t)
                    }).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    })
                },
                _parse_item: function(e, t) {
                    t = JSON.parse(t);
                    for (var n = 0; n < t.entry.length; n++) {
                        var o = t.entry[n],
                            a = /^[^\\\/!@#$%\^&\*\(\):\s]*$/i,
                            i = {
                                item_form: e.get("_template_form_item"),
                                is_input: e.get("is_input"),
                                item_disabled_state: !1,
                                enable_reload: !1,
                                item_name: o.name,
                                supports_credential: e.get("supports_credential"),
                                data_options: [{
                                    id: "edit_link",
                                    value: o.links.edit
                                }, {
                                    id: "remove_link",
                                    value: o.links.remove
                                }, {
                                    id: "stanza_name",
                                    value: o.name
                                }, {
                                    id: "disabled",
                                    value: o.content.disabled
                                }, {
                                    id: "mi_name",
                                    value: e.get("mi_name")
                                }],
                                items: {
                                    proxy_host: o.content.proxy_host,
                                    proxy_port: o.content.proxy_port,
                                    use_ssl: "1" === o.content.use_ssl ? 'checked="checked"' : ""
                                }
                            };
                        o.content.hasOwnProperty("proxy_user") ? (i.items.proxy_user = null === o.content.proxy_user.match(a) ? decodeURIComponent(o.content.proxy_user) : o.content.proxy_user, i.items.proxy_credential = o.content.proxy_credential) : (i.items.proxy_user = "N/A", i.items.proxy_credential = "N/A"), e._display_item(e, i)
                    }
                },
                _submit_new_proxy: function(e, t) {
                    var n = e._validate_data(e, e.prep_data(o(t).serializeArray()));
                    return !!n.status && (e.reset_message(e.get("modal_id") + "_msg_box"), void e._create_item(e, {
                        endpoint: "configs/conf-proxy",
                        data: n.data,
                        done: function(e, t) {
                            var a = JSON.parse(t);
                            a.content = a.entry[0].content, "none" != a.content.proxy_credential && e.create_credential({
                                user: a.content.proxy_credential,
                                password: n.proxy_password,
                                error: function(t) {
                                    e._generic_error_request(e.get("msg_box"), t)
                                },
                                done: function(e) {}
                            }), e._parse_item(e, JSON.stringify(a)), e.display_message(e.get("modal_id") + "_msg_box", " Proxy Configuration Added"), o('form[name="' + e.get("modal_id") + '_configuration"').trigger("reset")
                        }
                    }))
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "proxy_host":
                        case "proxy_user":
                        case "proxy_password":
                            return t.length >= 1;
                        case "proxy_name":
                            if (t.length < 1) return !1;
                            var n = t.match(/[0-9a-zA-Z_]+/)[0];
                            return !(n.length < t.length) && this.get("mi_name") + "://" + t;
                        case "proxy_port":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t > 65535);
                        default:
                            return !0
                    }
                },
                update_credential: function(e) {
                    var t = e.t,
                        n = e.f,
                        a = e.v,
                        i = e.i,
                        s = e.d;
                    t.get_credential({
                        t: t,
                        user: e.ed.user,
                        realm: t.get("app"),
                        done: function(r) {
                            if (r.entry.length > 0) {
                                var l = r.entry[0].content.username;
                                l != e.ed.user && (l = l.split("_")[1], t.update_property({
                                    e: "proxy",
                                    i: i,
                                    f: "proxy_user",
                                    v: l,
                                    t: t,
                                    d: s
                                }), o("#" + i + '_configuration input[name="proxy_credential"]').data({
                                    user: l
                                })), t.update_property({
                                    e: "proxy",
                                    i: i,
                                    f: n,
                                    v: a,
                                    d: s,
                                    t: t
                                })
                            } else t.display_error(i + "_msg", "Credential Stanza Doesn't Exist.")
                        }
                    })
                },
                _validate_data: function(e, t) {
                    if (t.hasOwnProperty("use_ssl") || (t.use_ssl = "false"), !e._validate_object("proxy_name", t.proxy_name)) return this.display_error(this.get("modal_id") + "_msg_box", "Proxy Name contains non-authorized characters"), !1;
                    if (t.name = t.proxy_name, delete t.proxy_name, !e._validate_object("proxy_host", t.proxy_host)) return this.display_error(this.get("modal_id") + "_msg_box", "Proxy Host is required"), !1;
                    if (!e._validate_object("proxy_port", t.proxy_port)) return this.display_error(this.get("modal_id") + "_msg_box", "Proxy Port is required, and can only be numbers and less than 65535."), !1;
                    var n = t.proxy_password;
                    return this.reset_message(this.get("modal_id") + "_msg_box"), e._validate_object("proxy_user", t.proxy_user) ? t.proxy_credential = t.proxy_host + "_" + t.proxy_user : t.proxy_credential = "none", delete t.proxy_password, {
                        data: t,
                        proxy_password: n,
                        status: !0
                    }
                },
                _setup_button: function() {
                    this.set({
                        button_id: this.add_button("Create New Proxy", !0)
                    })
                }
            })
        }.apply(t, o), !(void 0 !== a && (e.exports = a))
    }, function(e, t, n) {
        var o, a;
        o = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, o, a, i) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var o = e.extend.call(this, t, n);
                    if (o.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) o.prototype.defaults[a] || (o.prototype.defaults[a] = this.prototype.defaults[a]);
                    return o
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: i.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: i.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = o(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    o(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            i = a.entry[0].content.search;
                        o(t).val(i), o(t).data("evt_name", e.get("base_eventtype"))
                    }), o("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = o(t).data();
                        e._update_eventtype(a.evt_name, o(t).val())
                    }), o("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        o = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        o.display_error(o.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, o.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    o(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), o("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), o(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, o.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        o = e.t;
                    o.service.request(o._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(o.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var o = e[n].name,
                            a = e[n].value;
                        t[o] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = o("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        i = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(i), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = o("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        i = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(i), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = o("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        i = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(i), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = o("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        i = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? o("#" + this.get("tab_content_id")).prepend(s) : o("#" + this.get("button_container")).append(s), o("#" + n).on("click", function(e) {
                        a.each(i.get("modal_defaults"), function(e, t) {
                            i._set_modal_default(i.get("modal_id"), t, e)
                        }), o("#" + i.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    o(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    o("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return o("#" + this.get("tab_content_container")).append(n), o("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), o(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), o(this).css("class", "active");
                        var n = o(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), o(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    o("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        i = e.create_item(t);
                    o(n).append(i.html), o("#" + i.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), o("#" + i.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), o('form[name="' + i.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), o('form[name="' + i.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: i.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: i.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: i.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = o(t).data().name,
                        a = o("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        o("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    o("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        o = e >= 60;
                    return t || n || o
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = o(t).data().name,
                        a = o("#" + n + "_data_configuration").data(),
                        i = a.disabled,
                        s = !i,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        d = a.edit_link,
                        c = e.get("msg_box");
                    e.service.request(d, "POST", null, null, o.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(i) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            o(t).css("color", r), o(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), o("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(c, "Disabled: " + s), o("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = o(t),
                        a = n.data(),
                        i = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        d = !1;
                    i.includes("[]") && (l = [], o(o("#" + s + '_configuration input:checkbox:checked[name="' + i + '"]')).each(function(e) {
                        l[e] = o(this).val()
                    }), o("#" + s + '_configuration input[id="' + i.replace("[]", "") + '"]').each(function(e) {
                        var t = o(this).val();
                        t.length > 1 && (l[l.length] = o(this).val())
                    }), l = l.join(","), r = i.replace("[]", ""), d = !0);
                    var c = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (o(c).length > 0 && !d) {
                        var _ = [];
                        o(o("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            _[e] = o(this).val()
                        }), _[_.length] = l, l = _.join(","), d = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, o.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, o) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = o(t),
                        a = n.data(),
                        i = a.id,
                        s = n[0].id,
                        r = o("#" + i + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var d = l.v;
                    if ("must_have" in a && (s = a.must_have, d = o("#" + i + '_configuration input[id="' + a.must_have + '"]').val()), d = d.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (d = n.is(":checked") ? "true" : "false"), e._validate_object(s, d)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: i,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: i,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            }), e.update_property({
                                e: a.config_type,
                                i: i,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: i,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            })
                    } else e.display_error(i + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        i = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = o.param({
                            value: i
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        i = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            i.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = o("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(i, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        i = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: i.guid()
                            })
                        }
                        var l = o("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        i = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            i.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = o("#" + t + "_list_indexes");
                        l.empty(), a.each(i, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, o), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = o
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = i
    }, , , , , , , , function(e, t) {
        e.exports = '<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Proxy Name</label>\n    <div class="controls controls-block">\n        <input type="text" id="proxy_name" name="proxy_name" required="required"/>\n\n        <span class="help-block ">A unique identifier. Can only contain letters,\n            numbers and underscores.\n        </span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Host</label>\n    <div class="controls controls-block">\n        <input type="text" id="proxy_host" name="proxy_host" required="required"/>\n\n        <span class="help-block ">This is the FQDN, IP, or hostname of the proxy.\n        </span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Port</label>\n    <div class="controls controls-block">\n        <input type="text" id="proxy_port" name="proxy_port" required="required"/>\n        <span class="help-block ">Can only contain numbers.</span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Username</label>\n    <div class="controls controls-block">\n        <input type="text" id="proxy_user" name="proxy_user"/>\n        <span class="help-block ">Optional.</span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Password</label>\n    <div class="controls controls-block">\n        <input type="password" id="proxy_password" name="proxy_password"/>\n        <span class="help-block ">Optional.</span>\n    </div>\n</div>\n<div class="control-group shared-controls-controlgroup control-group-default">\n    <label class="control-label">Use SSL?</label>\n    <div class="controls controls-block">\n        <input type="checkbox" id="use_ssl" name="use_ssl" value="true"/>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="controls controls-fill">\n    <label class="control-label">Proxy Host:</label>\n    <input type="text" class="input-medium proxy_host" data-update_type="proxy" data-id="{{item_id}}" id="proxy_host"\n           name="proxy_host" value="{{items.proxy_host}}"/>\n</div>\n<div class="controls controls-fill">\n    <label class="control-label">Proxy Port:</label>\n    <input type="text" class="input-medium proxy_port" data-update_type="proxy" data-id="{{item_id}}" id="proxy_port"\n           name="proxy_port" value="{{items.proxy_port}}"/>\n</div>\n\n<div class="controls controls-fill">\n    <label class="control-label">Username:</label>\n    <input type="text" class="input-medium proxy_user" data-update_type="proxy" data-id="{{item_id}}" id="proxy_user"\n           name="proxy_user" value="{{items.proxy_user}}"/>\n</div>\n<!--<input type="text" class="input-medium proxy_credential" data-id="{{item_id}}" id="proxy_credential" name="proxy_credential"  value="{{items.proxy_credential}}" disabled="disabled" />-->\n<div class="controls controls-fill">\n    <label class="control-label">Credential:</label>\n    <input type="text" oninput="this.title = this.value" title="{{items.proxy_credential}}" data-update_type="proxy"\n           class="input-medium credential_realm" data-id="{{item_id}}" id="proxy_credential" name="proxy_credential"\n           value="{{items.proxy_credential}}"/>\n</div>\n<div class="controls controls-fill">\n    <label class="control-label">Use SSL:</label>\n    <input type="checkbox" data-id="{{item_id}}" id="use_ssl" name="use_ssl" {{items.use_ssl}}\n           data-update_type="checkbox" data-config_type="proxy"/>\n</div>'
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_readme", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, r, i, o) {
    return function(e) {
        function t(r) {
            if (n[r]) return n[r].exports;
            var i = n[r] = {
                exports: {},
                id: r,
                loaded: !1
            };
            return e[r].call(i.exports, i, i.exports, t), i.loaded = !0, i.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var r, i;
        r = [n(2), n(1), n(3), n(4), n(5), n(10), n(20)], i = function(e, t, n, r, i, a, o) {
            return t.fullExtend({
                defaults: {},
            })
        }.apply(t, r), !(void 0 !== i && (e.exports = i))
    }, function(e, t, n) {
        var r, i;
        r = [n(2), n(6), n(3), n(4), n(5)], i = function(e, t, r, i, a) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var r = e.extend.call(this, t, n);
                    if (r.prototype._super = this.prototype, t.defaults)
                        for (var i in this.prototype.defaults) r.prototype.defaults[i] || (r.prototype.defaults[i] = this.prototype.defaults[i]);
                    return r
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: a.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: a.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = r(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    r(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var i = JSON.parse(n),
                            a = i.entry[0].content.search;
                        r(t).val(a), r(t).data("evt_name", e.get("base_eventtype"))
                    }), r("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var i = r(t).data();
                        e._update_eventtype(i.evt_name, r(t).val())
                    }), r("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        r = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        r.display_error(r.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "POST", null, null, r.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        i.display_message(i.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return i.template(i.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    r(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), r("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), r(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, r.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        r = e.t;
                    r.service.request(r._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        r._generic_error_request(r.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(r.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var r = e[n].name,
                            i = e[n].value;
                        t[r] = i
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = r("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + i.escape(t) + "</strong>" : ""),
                        a = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(a), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = r("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + i.escape(t) + "</strong>" : ""),
                        a = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(a), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = r("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + i.escape(t) + "</strong>" : ""),
                        a = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(a), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = r("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        a = this,
                        o = '<button type="button" id="' + i.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? r("#" + this.get("tab_content_id")).prepend(o) : r("#" + this.get("button_container")).append(o), r("#" + n).on("click", function(e) {
                        i.each(a.get("modal_defaults"), function(e, t) {
                            a._set_modal_default(a.get("modal_id"), t, e)
                        }), r("#" + a.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    r(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    r("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = i.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return r("#" + this.get("tab_content_container")).append(n), r("#" + this.get("tab_container")).append('<li title="' + i.escape(e.tab_xref) + ' Tab"><a  href="#' + i.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + i.escape(e.tab_id) + '">' + i.escape(e.text) + "</li>"), r(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), r(this).css("class", "active");
                        var n = r(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), r(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    r("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: i.template(i.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == i.escape(e.get("supports_proxy")), t.is_input = "true" == i.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        a = e.create_item(t);
                    r(n).append(a.html), r("#" + a.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), r("#" + a.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), r('form[name="' + a.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), r('form[name="' + a.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: a.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: a.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: a.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = r(t).data().name,
                        i = r("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + i.stanza_name + "?") && void e.service.del(i.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        r("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    r("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        r = e >= 60;
                    return t || n || r
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = r(t).data().name,
                        i = r("#" + n + "_data_configuration").data(),
                        a = i.disabled,
                        o = !a,
                        s = o ? "#d6563c" : "#65a637",
                        l = o ? " icon-minus-circle " : " icon-check-circle",
                        c = i.edit_link,
                        u = e.get("msg_box");
                    e.service.request(c, "POST", null, null, r.param({
                        disabled: o.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(a) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(i.mi_name) + "/_reload"), "GET").done(function(i) {
                            r(t).css("color", s), r(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), r("#" + n + "_data_configuration").data({
                                disabled: o
                            }), e.display_message(u, "Disabled: " + o), r("#" + n + "_enablement").text(o ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = r(t),
                        i = n.data(),
                        a = n[0].name,
                        o = i.id,
                        s = n[0].id,
                        l = n.val(),
                        c = !1;
                    a.includes("[]") && (l = [], r(r("#" + o + '_configuration input:checkbox:checked[name="' + a + '"]')).each(function(e) {
                        l[e] = r(this).val()
                    }), r("#" + o + '_configuration input[id="' + a.replace("[]", "") + '"]').each(function(e) {
                        var t = r(this).val();
                        t.length > 1 && (l[l.length] = r(this).val())
                    }), l = l.join(","), s = a.replace("[]", ""), c = !0);
                    var u = "#" + o + '_configuration input:checkbox:checked[name="' + s + '[]"]';
                    if (r(u).length > 0 && !c) {
                        var d = [];
                        r(r("#" + o + '_configuration input:checkbox:checked[name="' + s + '[]"]')).each(function(e) {
                            d[e] = r(this).val()
                        }), d[d.length] = l, l = d.join(","), c = !0
                    }
                    return {
                        f: s,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, r.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, r) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = r(t),
                        i = n.data(),
                        a = i.id,
                        o = n[0].id,
                        s = r("#" + a + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    o = l.f;
                    var c = l.v;
                    if ("must_have" in i && (o = i.must_have, c = r("#" + a + '_configuration input[id="' + i.must_have + '"]').val()), c = c.replace(/,+$/, ""), "update_type" in i && "checkbox" === i.update_type && (c = n.is(":checked") ? "true" : "false"), e._validate_object(o, c)) switch (i.update_type || (i.update_type = "inputs"), i.update_type) {
                        case "up":
                            e.update_credential({
                                i: a,
                                t: e,
                                ed: i,
                                d: s,
                                f: o,
                                v: c
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: i.config_type,
                                i: a,
                                t: e,
                                d: s,
                                f: o,
                                v: c
                            }), e.update_property({
                                e: i.config_type,
                                i: a,
                                t: e,
                                d: s,
                                f: o,
                                v: c
                            });
                            break;
                        default:
                            e.update_property({
                                e: i.update_type,
                                i: a,
                                t: e,
                                d: s,
                                f: o,
                                v: c
                            })
                    } else e.display_error(a + "_msg", o + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        i = e.f,
                        a = e.v,
                        o = e.i,
                        s = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + i),
                        l = r.param({
                            value: a
                        });
                    t.service.request(s, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(o + "_msg", i + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        a = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        o = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var o = 0; o < e.entry.length; o++) {
                            var s = e.entry[o].name;
                            a.push({
                                selected: s == n ? " selected " : "",
                                name: s,
                                value: s
                            })
                        }
                        var l = r("#" + t + ' select[name="proxy_name"]');
                        l.empty(), i.each(a, function(e) {
                            l.append("<option " + i.escape(e.selected) + " value='" + i.escape(e.value) + "'>" + i.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        a = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        a._generic_error_request(a.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var o = 0; o < e.entry.length; o++) {
                            var s = e.entry[o].content;
                            n.push({
                                username: s.username,
                                realm: s.realm,
                                value: a.guid()
                            })
                        }
                        var l = r("#" + t + "_list_credentials");
                        l.empty(), i.each(n, function(e) {
                            l.append("<option id='" + i.escape(e.realm) + "' data-realm='" + i.escape(e.realm) + "' data-user='" + i.escape(e.username) + "' value='" + i.escape(e.realm) + "'>" + i.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        a = [],
                        o = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var o = 0; o < e.entry.length; o++) {
                            var s = e.entry[o].name;
                            a.push({
                                selected: s == n ? " selected " : "",
                                name: s,
                                value: s
                            })
                        }
                        var l = r("#" + t + "_list_indexes");
                        l.empty(), i.each(a, function(e) {
                            l.append("<option " + i.escape(e.selected) + " value='" + i.escape(e.value) + "'>" + i.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, r), !(void 0 !== i && (e.exports = i))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = r
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = o
    }, , , , , , , , , , function(e, t, n) {
        ! function(e) {
            function t() {
                return "Markdown.mk_block( " + uneval(this.toString()) + ", " + uneval(this.trailing) + ", " + uneval(this.lineNumber) + " )"
            }

            function r() {
                var e = n(21);
                return "Markdown.mk_block( " + e.inspect(this.toString()) + ", " + e.inspect(this.trailing) + ", " + e.inspect(this.lineNumber) + " )"
            }

            function i(e) {
                for (var t = 0, n = -1;
                    (n = e.indexOf("\n", n + 1)) !== -1;) t++;
                return t
            }

            function o(e, t) {
                function n(e) {
                    this.len_after = e, this.name = "close_" + t
                }
                var r = e + "_state",
                    i = "strong" == e ? "em_state" : "strong_state";
                return function(a, o) {
                    if (this[r][0] == t) return this[r].shift(), [a.length, new n(a.length - t.length)];
                    var s = this[i].slice(),
                        l = this[r].slice();
                    this[r].unshift(t);
                    var c = this.processInline(a.substr(t.length)),
                        u = c[c.length - 1];
                    this[r].shift();
                    if (u instanceof n) {
                        c.pop();
                        var d = a.length - u.len_after;
                        return [d, [e].concat(c)]
                    }
                    return this[i] = s, this[r] = l, [t.length, t]
                }
            }

            function s(e) {
                for (var t = e.split(""), n = [""], r = !1; t.length;) {
                    var i = t.shift();
                    switch (i) {
                        case " ":
                            r ? n[n.length - 1] += i : n.push("");
                            break;
                        case "'":
                        case '"':
                            r = !r;
                            break;
                        case "\\":
                            i = t.shift();
                        default:
                            n[n.length - 1] += i
                    }
                }
                return n
            }

            function l(e) {
                return m(e) && e.length > 1 && "object" == typeof e[1] && !m(e[1]) ? e[1] : void 0
            }

            function c(e) {
                return e.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;")
            }

            function u(e) {
                if ("string" == typeof e) return c(e);
                var t = e.shift(),
                    n = {},
                    r = [];
                for (!e.length || "object" != typeof e[0] || e[0] instanceof Array || (n = e.shift()); e.length;) r.push(u(e.shift()));
                var i = "";
                for (var a in n) i += " " + a + '="' + c(n[a]) + '"';
                return "img" == t || "br" == t || "hr" == t ? "<" + t + i + "/>" : "<" + t + i + ">" + r.join("") + "</" + t + ">"
            }

            function d(e, t, n) {
                var r;
                n = n || {};
                var i = e.slice(0);
                "function" == typeof n.preprocessTreeNode && (i = n.preprocessTreeNode(i, t));
                var a = l(i);
                if (a) {
                    i[1] = {};
                    for (r in a) i[1][r] = a[r];
                    a = i[1]
                }
                if ("string" == typeof i) return i;
                switch (i[0]) {
                    case "header":
                        i[0] = "h" + i[1].level, delete i[1].level;
                        break;
                    case "bulletlist":
                        i[0] = "ul";
                        break;
                    case "numberlist":
                        i[0] = "ol";
                        break;
                    case "listitem":
                        i[0] = "li";
                        break;
                    case "para":
                        i[0] = "p";
                        break;
                    case "markdown":
                        i[0] = "html", a && delete a.references;
                        break;
                    case "code_block":
                        i[0] = "pre", r = a ? 2 : 1;
                        var o = ["code"];
                        o.push.apply(o, i.splice(r, i.length - r)), i[r] = o;
                        break;
                    case "inlinecode":
                        i[0] = "code";
                        break;
                    case "img":
                        i[1].src = i[1].href, delete i[1].href;
                        break;
                    case "linebreak":
                        i[0] = "br";
                        break;
                    case "link":
                        i[0] = "a";
                        break;
                    case "link_ref":
                        i[0] = "a";
                        var s = t[a.ref];
                        if (!s) return a.original;
                        delete a.ref, a.href = s.href, s.title && (a.title = s.title), delete a.original;
                        break;
                    case "img_ref":
                        i[0] = "img";
                        var s = t[a.ref];
                        if (!s) return a.original;
                        delete a.ref, a.src = s.href, s.title && (a.title = s.title), delete a.original
                }
                if (r = 1, a) {
                    for (var c in i[1]) {
                        r = 2;
                        break
                    }
                    1 === r && i.splice(r, 1)
                }
                for (; r < i.length; ++r) i[r] = d(i[r], t, n);
                return i
            }

            function f(e) {
                for (var t = l(e) ? 2 : 1; t < e.length;) "string" == typeof e[t] ? t + 1 < e.length && "string" == typeof e[t + 1] ? e[t] += e.splice(t + 1, 1)[0] : ++t : (f(e[t]), ++t)
            }
            var _ = e.Markdown = function(e) {
                switch (typeof e) {
                    case "undefined":
                        this.dialect = _.dialects.Gruber;
                        break;
                    case "object":
                        this.dialect = e;
                        break;
                    default:
                        if (!(e in _.dialects)) throw new Error("Unknown Markdown dialect '" + String(e) + "'");
                        this.dialect = _.dialects[e]
                }
                this.em_state = [], this.strong_state = [], this.debug_indent = ""
            };
            e.parse = function(e, t) {
                var n = new _(t);
                return n.toTree(e)
            }, e.toHTML = function(t, n, r) {
                var i = e.toHTMLTree(t, n, r);
                return e.renderJsonML(i)
            }, e.toHTMLTree = function(e, t, n) {
                "string" == typeof e && (e = this.parse(e, t));
                var r = l(e),
                    i = {};
                r && r.references && (i = r.references);
                var a = d(e, i, n);
                return f(a), a
            };
            var h = _.mk_block = function(e, n, i) {
                1 == arguments.length && (n = "\n\n");
                var a = new String(e);
                return a.trailing = n, a.inspect = r, a.toSource = t, void 0 != i && (a.lineNumber = i), a
            };
            _.prototype.split_blocks = function(e, t) {
                e = e.replace(/(\r\n|\n|\r)/g, "\n");
                var n, r = /([\s\S]+?)($|\n#|\n(?:\s*\n|$)+)/g,
                    a = [],
                    o = 1;
                for (null != (n = /^(\s*\n)/.exec(e)) && (o += i(n[0]), r.lastIndex = n[0].length); null !== (n = r.exec(e));) "\n#" == n[2] && (n[2] = "\n", r.lastIndex--), a.push(h(n[1], n[2], o)), o += i(n[0]);
                return a
            }, _.prototype.processBlock = function(e, t) {
                var n = this.dialect.block,
                    r = n.__order__;
                if ("__call__" in n) return n.__call__.call(this, e, t);
                for (var i = 0; i < r.length; i++) {
                    var a = n[r[i]].call(this, e, t);
                    if (a) return (!m(a) || a.length > 0 && !m(a[0])) && this.debug(r[i], "didn't return a proper array"), a
                }
                return []
            }, _.prototype.processInline = function(e) {
                return this.dialect.inline.__call__.call(this, String(e))
            }, _.prototype.toTree = function(e, t) {
                var n = e instanceof Array ? e : this.split_blocks(e),
                    r = this.tree;
                try {
                    for (this.tree = t || this.tree || ["markdown"]; n.length;) {
                        var i = this.processBlock(n.shift(), n);
                        i.length && this.tree.push.apply(this.tree, i)
                    }
                    return this.tree
                } finally {
                    t && (this.tree = r)
                }
            }, _.prototype.debug = function() {
                var e = Array.prototype.slice.call(arguments);
                e.unshift(this.debug_indent), "undefined" != typeof print && print.apply(print, e), "undefined" != typeof console && "undefined" != typeof console.log && console.log.apply(null, e)
            }, _.prototype.loop_re_over_block = function(e, t, n) {
                for (var r, i = t.valueOf(); i.length && null != (r = e.exec(i));) i = i.substr(r[0].length), n.call(this, r);
                return i
            }, _.dialects = {}, _.dialects.Gruber = {
                block: {
                    atxHeader: function(e, t) {
                        var n = e.match(/^(#{1,6})\s*(.*?)\s*#*\s*(?:\n|$)/);
                        if (n) {
                            var r = ["header", {
                                level: n[1].length
                            }];
                            return Array.prototype.push.apply(r, this.processInline(n[2])), n[0].length < e.length && t.unshift(h(e.substr(n[0].length), e.trailing, e.lineNumber + 2)), [r]
                        }
                    },
                    setextHeader: function(e, t) {
                        var n = e.match(/^(.*)\n([-=])\2\2+(?:\n|$)/);
                        if (n) {
                            var r = "=" === n[2] ? 1 : 2,
                                i = ["header", {
                                    level: r
                                }, n[1]];
                            return n[0].length < e.length && t.unshift(h(e.substr(n[0].length), e.trailing, e.lineNumber + 2)), [i]
                        }
                    },
                    code: function(e, t) {
                        var n = [],
                            r = /^(?: {0,3}\t| {4})(.*)\n?/;
                        if (e.match(r)) {
                            e: for (;;) {
                                var i = this.loop_re_over_block(r, e.valueOf(), function(e) {
                                    n.push(e[1])
                                });
                                if (i.length) {
                                    t.unshift(h(i, e.trailing));
                                    break e
                                }
                                if (!t.length) break e;
                                if (!t[0].match(r)) break e;
                                n.push(e.trailing.replace(/[^\n]/g, "").substring(2)), e = t.shift()
                            }
                            return [
                                ["code_block", n.join("\n")]
                            ]
                        }
                    },
                    horizRule: function(e, t) {
                        var n = e.match(/^(?:([\s\S]*?)\n)?[ \t]*([-_*])(?:[ \t]*\2){2,}[ \t]*(?:\n([\s\S]*))?$/);
                        if (n) {
                            var r = [
                                ["hr"]
                            ];
                            return n[1] && r.unshift.apply(r, this.processBlock(n[1], [])), n[3] && t.unshift(h(n[3])), r
                        }
                    },
                    lists: function() {
                        function e(e) {
                            return new RegExp("(?:^(" + l + "{0," + e + "} {0,3})(" + a + ")\\s+)|(^" + l + "{0," + (e - 1) + "}[ ]{0,4})")
                        }

                        function t(e) {
                            return e.replace(/ {0,3}\t/g, "    ")
                        }

                        function n(e, t, n, r) {
                            if (t) return void e.push(["para"].concat(n));
                            var i = e[e.length - 1] instanceof Array && "para" == e[e.length - 1][0] ? e[e.length - 1] : e;
                            r && e.length > 1 && n.unshift(r);
                            for (var a = 0; a < n.length; a++) {
                                var o = n[a],
                                    s = "string" == typeof o;
                                s && i.length > 1 && "string" == typeof i[i.length - 1] ? i[i.length - 1] += o : i.push(o)
                            }
                        }

                        function r(e, t) {
                            for (var n = new RegExp("^(" + l + "{" + e + "}.*?\\n?)*$"), r = new RegExp("^" + l + "{" + e + "}", "gm"), i = []; t.length > 0 && n.exec(t[0]);) {
                                var a = t.shift(),
                                    o = a.replace(r, "");
                                i.push(h(o, a.trailing, a.lineNumber))
                            }
                            return i
                        }

                        function i(e, t, n) {
                            var r = e.list,
                                i = r[r.length - 1];
                            if (!(i[1] instanceof Array && "para" == i[1][0]))
                                if (t + 1 == n.length) i.push(["para"].concat(i.splice(1, i.length - 1)));
                                else {
                                    var a = i.pop();
                                    i.push(["para"].concat(i.splice(1, i.length - 1)), a)
                                }
                        }
                        var a = "[*+-]|\\d+\\.",
                            o = /[*+-]/,
                            s = new RegExp("^( {0,3})(" + a + ")[ \t]+"),
                            l = "(?: {0,3}\\t| {4})";
                        return function(a, l) {
                            function c(e) {
                                var t = o.exec(e[2]) ? ["bulletlist"] : ["numberlist"];
                                return f.push({
                                    list: t,
                                    indent: e[1]
                                }), t
                            }
                            var u = a.match(s);
                            if (u) {
                                for (var d, p, f = [], _ = c(u), h = !1, m = [f[0].list];;) {
                                    for (var v = a.split(/(?=\n)/), b = "", y = 0; y < v.length; y++) {
                                        var x = "",
                                            k = v[y].replace(/^\n/, function(e) {
                                                return x = e, ""
                                            }),
                                            w = e(f.length);
                                        if (u = k.match(w), void 0 !== u[1]) {
                                            b.length && (n(d, h, this.processInline(b), x), h = !1, b = ""), u[1] = t(u[1]);
                                            var S = Math.floor(u[1].length / 4) + 1;
                                            if (S > f.length) _ = c(u), d.push(_), d = _[1] = ["listitem"];
                                            else {
                                                var T = !1;
                                                for (p = 0; p < f.length; p++)
                                                    if (f[p].indent == u[1]) {
                                                        _ = f[p].list, f.splice(p + 1, f.length - (p + 1)), T = !0;
                                                        break
                                                    } T || (S++, S <= f.length ? (f.splice(S, f.length - S), _ = f[S - 1].list) : (_ = c(u), d.push(_))), d = ["listitem"], _.push(d)
                                            }
                                            x = ""
                                        }
                                        k.length > u[0].length && (b += x + k.substr(u[0].length))
                                    }
                                    b.length && (n(d, h, this.processInline(b), x), h = !1, b = "");
                                    var O = r(f.length, l);
                                    O.length > 0 && (g(f, i, this), d.push.apply(d, this.toTree(O, [])));
                                    var j = l[0] && l[0].valueOf() || "";
                                    if (!j.match(s) && !j.match(/^ /)) break;
                                    a = l.shift();
                                    var E = this.dialect.block.horizRule(a, l);
                                    if (E) {
                                        m.push.apply(m, E);
                                        break
                                    }
                                    g(f, i, this), h = !0
                                }
                                return m
                            }
                        }
                    }(),
                    blockquote: function(e, t) {
                        if (e.match(/^>/m)) {
                            var n = [];
                            if (">" != e[0]) {
                                for (var r = e.split(/\n/), i = [], a = e.lineNumber; r.length && ">" != r[0][0];) i.push(r.shift()), a++;
                                var o = h(i.join("\n"), "\n", e.lineNumber);
                                n.push.apply(n, this.processBlock(o, [])), e = h(r.join("\n"), e.trailing, a)
                            }
                            for (; t.length && ">" == t[0][0];) {
                                var s = t.shift();
                                e = h(e + e.trailing + s, s.trailing, e.lineNumber);
                            }
                            var c = e.replace(/^> ?/gm, ""),
                                u = (this.tree, this.toTree(c, ["blockquote"])),
                                d = l(u);
                            return d && d.references && (delete d.references, v(d) && u.splice(1, 1)), n.push(u), n
                        }
                    },
                    referenceDefn: function(e, t) {
                        var n = /^\s*\[(.*?)\]:\s*(\S+)(?:\s+(?:(['"])(.*?)\3|\((.*?)\)))?\n?/;
                        if (e.match(n)) {
                            l(this.tree) || this.tree.splice(1, 0, {});
                            var r = l(this.tree);
                            void 0 === r.references && (r.references = {});
                            var i = this.loop_re_over_block(n, e, function(e) {
                                e[2] && "<" == e[2][0] && ">" == e[2][e[2].length - 1] && (e[2] = e[2].substring(1, e[2].length - 1));
                                var t = r.references[e[1].toLowerCase()] = {
                                    href: e[2]
                                };
                                void 0 !== e[4] ? t.title = e[4] : void 0 !== e[5] && (t.title = e[5])
                            });
                            return i.length && t.unshift(h(i, e.trailing)), []
                        }
                    },
                    para: function(e, t) {
                        return [
                            ["para"].concat(this.processInline(e))
                        ]
                    }
                }
            }, _.dialects.Gruber.inline = {
                __oneElement__: function(e, t, n) {
                    var r, i;
                    t = t || this.dialect.inline.__patterns__;
                    var a = new RegExp("([\\s\\S]*?)(" + (t.source || t) + ")");
                    if (r = a.exec(e), !r) return [e.length, e];
                    if (r[1]) return [r[1].length, r[1]];
                    var i;
                    return r[2] in this.dialect.inline && (i = this.dialect.inline[r[2]].call(this, e.substr(r.index), r, n || [])), i = i || [r[2].length, r[2]]
                },
                __call__: function(e, t) {
                    function n(e) {
                        "string" == typeof e && "string" == typeof i[i.length - 1] ? i[i.length - 1] += e : i.push(e)
                    }
                    for (var r, i = []; e.length > 0;) r = this.dialect.inline.__oneElement__.call(this, e, t, i), e = e.substr(r.shift()), g(r, n);
                    return i
                },
                "]": function() {},
                "}": function() {},
                __escape__: /^\\[\\`\*_{}\[\]()#\+.!\-]/,
                "\\": function(e) {
                    return this.dialect.inline.__escape__.exec(e) ? [2, e.charAt(1)] : [1, "\\"]
                },
                "![": function(e) {
                    var t = e.match(/^!\[(.*?)\][ \t]*\([ \t]*([^")]*?)(?:[ \t]+(["'])(.*?)\3)?[ \t]*\)/);
                    if (t) {
                        t[2] && "<" == t[2][0] && ">" == t[2][t[2].length - 1] && (t[2] = t[2].substring(1, t[2].length - 1)), t[2] = this.dialect.inline.__call__.call(this, t[2], /\\/)[0];
                        var n = {
                            alt: t[1],
                            href: t[2] || ""
                        };
                        return void 0 !== t[4] && (n.title = t[4]), [t[0].length, ["img", n]]
                    }
                    return t = e.match(/^!\[(.*?)\][ \t]*\[(.*?)\]/), t ? [t[0].length, ["img_ref", {
                        alt: t[1],
                        ref: t[2].toLowerCase(),
                        original: t[0]
                    }]] : [2, "!["]
                },
                "[": function e(t) {
                    var n = String(t),
                        r = _.DialectHelpers.inline_until_char.call(this, t.substr(1), "]");
                    if (!r) return [1, "["];
                    var e, i, a = 1 + r[0],
                        o = r[1];
                    t = t.substr(a);
                    var s = t.match(/^\s*\([ \t]*([^"']*)(?:[ \t]+(["'])(.*?)\2)?[ \t]*\)/);
                    if (s) {
                        var l = s[1];
                        if (a += s[0].length, l && "<" == l[0] && ">" == l[l.length - 1] && (l = l.substring(1, l.length - 1)), !s[3])
                            for (var c = 1, u = 0; u < l.length; u++) switch (l[u]) {
                                case "(":
                                    c++;
                                    break;
                                case ")":
                                    0 == --c && (a -= l.length - u, l = l.substring(0, u))
                            }
                        return l = this.dialect.inline.__call__.call(this, l, /\\/)[0], i = {
                            href: l || ""
                        }, void 0 !== s[3] && (i.title = s[3]), e = ["link", i].concat(o), [a, e]
                    }
                    return s = t.match(/^\s*\[(.*?)\]/), s ? (a += s[0].length, i = {
                        ref: (s[1] || String(o)).toLowerCase(),
                        original: n.substr(0, a)
                    }, e = ["link_ref", i].concat(o), [a, e]) : 1 == o.length && "string" == typeof o[0] ? (i = {
                        ref: o[0].toLowerCase(),
                        original: n.substr(0, a)
                    }, e = ["link_ref", i, o[0]], [a, e]) : [1, "["]
                },
                "<": function(e) {
                    var t;
                    return null != (t = e.match(/^<(?:((https?|ftp|mailto):[^>]+)|(.*?@.*?\.[a-zA-Z]+))>/)) ? t[3] ? [t[0].length, ["link", {
                        href: "mailto:" + t[3]
                    }, t[3]]] : "mailto" == t[2] ? [t[0].length, ["link", {
                        href: t[1]
                    }, t[1].substr("mailto:".length)]] : [t[0].length, ["link", {
                        href: t[1]
                    }, t[1]]] : [1, "<"]
                },
                "`": function(e) {
                    var t = e.match(/(`+)(([\s\S]*?)\1)/);
                    return t && t[2] ? [t[1].length + t[2].length, ["inlinecode", t[3]]] : [1, "`"]
                },
                "  \n": function(e) {
                    return [3, ["linebreak"]]
                }
            }, _.dialects.Gruber.inline["**"] = o("strong", "**"), _.dialects.Gruber.inline.__ = o("strong", "__"), _.dialects.Gruber.inline["*"] = o("em", "*"), _.dialects.Gruber.inline._ = o("em", "_"), _.buildBlockOrder = function(e) {
                var t = [];
                for (var n in e) "__order__" != n && "__call__" != n && t.push(n);
                e.__order__ = t
            }, _.buildInlinePatterns = function(e) {
                var t = [];
                for (var n in e)
                    if (!n.match(/^__.*__$/)) {
                        var r = n.replace(/([\\.*+?|()\[\]{}])/g, "\\$1").replace(/\n/, "\\n");
                        t.push(1 == n.length ? r : "(?:" + r + ")")
                    } t = t.join("|"), e.__patterns__ = t;
                var i = e.__call__;
                e.__call__ = function(e, n) {
                    return void 0 != n ? i.call(this, e, n) : i.call(this, e, t)
                }
            }, _.DialectHelpers = {}, _.DialectHelpers.inline_until_char = function(e, t) {
                for (var n = 0, r = [];;) {
                    if (e.charAt(n) == t) return n++, [n, r];
                    if (n >= e.length) return null;
                    var i = this.dialect.inline.__oneElement__.call(this, e.substr(n));
                    n += i[0], r.push.apply(r, i.slice(1))
                }
            }, _.subclassDialect = function(e) {
                function t() {}

                function n() {}
                return t.prototype = e.block, n.prototype = e.inline, {
                    block: new t,
                    inline: new n
                }
            }, _.buildBlockOrder(_.dialects.Gruber.block), _.buildInlinePatterns(_.dialects.Gruber.inline), _.dialects.Maruku = _.subclassDialect(_.dialects.Gruber), _.dialects.Maruku.processMetaHash = function(e) {
                for (var t = s(e), n = {}, r = 0; r < t.length; ++r)
                    if (/^#/.test(t[r])) n.id = t[r].substring(1);
                    else if (/^\./.test(t[r])) n.class ? n.class = n.class + t[r].replace(/./, " ") : n.class = t[r].substring(1);
                else if (/\=/.test(t[r])) {
                    var i = t[r].split(/\=/);
                    n[i[0]] = i[1]
                }
                return n
            }, _.dialects.Maruku.block.document_meta = function(e, t) {
                if (!(e.lineNumber > 1) && e.match(/^(?:\w+:.*\n)*\w+:.*$/)) {
                    l(this.tree) || this.tree.splice(1, 0, {});
                    var n = e.split(/\n/);
                    for (p in n) {
                        var r = n[p].match(/(\w+):\s*(.*)$/),
                            i = r[1].toLowerCase(),
                            a = r[2];
                        this.tree[1][i] = a
                    }
                    return []
                }
            }, _.dialects.Maruku.block.block_meta = function(e, t) {
                var n = e.match(/(^|\n) {0,3}\{:\s*((?:\\\}|[^\}])*)\s*\}$/);
                if (n) {
                    var r, i = this.dialect.processMetaHash(n[2]);
                    if ("" === n[1]) {
                        var o = this.tree[this.tree.length - 1];
                        if (r = l(o), "string" == typeof o) return;
                        r || (r = {}, o.splice(1, 0, r));
                        for (a in i) r[a] = i[a];
                        return []
                    }
                    var s = e.replace(/\n.*$/, ""),
                        c = this.processBlock(s, []);
                    r = l(c[0]), r || (r = {}, c[0].splice(1, 0, r));
                    for (a in i) r[a] = i[a];
                    return c
                }
            }, _.dialects.Maruku.block.definition_list = function(e, t) {
                var n, r, i = /^((?:[^\s:].*\n)+):\s+([\s\S]+)$/,
                    a = ["dl"];
                if (r = e.match(i)) {
                    for (var o = [e]; t.length && i.exec(t[0]);) o.push(t.shift());
                    for (var s = 0; s < o.length; ++s) {
                        var r = o[s].match(i),
                            l = r[1].replace(/\n$/, "").split(/\n/),
                            c = r[2].split(/\n:\s+/);
                        for (n = 0; n < l.length; ++n) a.push(["dt", l[n]]);
                        for (n = 0; n < c.length; ++n) a.push(["dd"].concat(this.processInline(c[n].replace(/(\n)\s+/, "$1"))))
                    }
                    return [a]
                }
            }, _.dialects.Maruku.block.table = function e(t, n) {
                var r, i, a = function(e, t) {
                        t = t || "\\s", t.match(/^[\\|\[\]{}?*.+^$]$/) && (t = "\\" + t);
                        for (var n, r = [], i = new RegExp("^((?:\\\\.|[^\\\\" + t + "])*)" + t + "(.*)"); n = e.match(i);) r.push(n[1]), e = n[2];
                        return r.push(e), r
                    },
                    o = /^ {0,3}\|(.+)\n {0,3}\|\s*([\-:]+[\-| :]*)\n((?:\s*\|.*(?:\n|$))*)(?=\n|$)/,
                    s = /^ {0,3}(\S(?:\\.|[^\\|])*\|.*)\n {0,3}([\-:]+\s*\|[\-| :]*)\n((?:(?:\\.|[^\\|])*\|.*(?:\n|$))*)(?=\n|$)/;
                if (i = t.match(o)) i[3] = i[3].replace(/^\s*\|/gm, "");
                else if (!(i = t.match(s))) return;
                var e = ["table", ["thead", ["tr"]],
                    ["tbody"]
                ];
                i[2] = i[2].replace(/\|\s*$/, "").split("|");
                var l = [];
                for (g(i[2], function(e) {
                        e.match(/^\s*-+:\s*$/) ? l.push({
                            align: "right"
                        }) : e.match(/^\s*:-+\s*$/) ? l.push({
                            align: "left"
                        }) : e.match(/^\s*:-+:\s*$/) ? l.push({
                            align: "center"
                        }) : l.push({})
                    }), i[1] = a(i[1].replace(/\|\s*$/, ""), "|"), r = 0; r < i[1].length; r++) e[1][1].push(["th", l[r] || {}].concat(this.processInline(i[1][r].trim())));
                return g(i[3].replace(/\|\s*$/gm, "").split("\n"), function(t) {
                    var n = ["tr"];
                    for (t = a(t, "|"), r = 0; r < t.length; r++) n.push(["td", l[r] || {}].concat(this.processInline(t[r].trim())));
                    e[2].push(n)
                }, this), [e]
            }, _.dialects.Maruku.inline["{:"] = function(e, t, n) {
                if (!n.length) return [2, "{:"];
                var r = n[n.length - 1];
                if ("string" == typeof r) return [2, "{:"];
                var i = e.match(/^\{:\s*((?:\\\}|[^\}])*)\s*\}/);
                if (!i) return [2, "{:"];
                var a = this.dialect.processMetaHash(i[1]),
                    o = l(r);
                o || (o = {}, r.splice(1, 0, o));
                for (var s in a) o[s] = a[s];
                return [i[0].length, ""]
            }, _.dialects.Maruku.inline.__escape__ = /^\\[\\`\*_{}\[\]()#\+.!\-|:]/, _.buildBlockOrder(_.dialects.Maruku.block), _.buildInlinePatterns(_.dialects.Maruku.inline);
            var g, m = Array.isArray || function(e) {
                return "[object Array]" == Object.prototype.toString.call(e)
            };
            g = Array.prototype.forEach ? function(e, t, n) {
                return e.forEach(t, n)
            } : function(e, t, n) {
                for (var r = 0; r < e.length; r++) t.call(n || e, e[r], r, e)
            };
            var v = function(e) {
                for (var t in e)
                    if (hasOwnProperty.call(e, t)) return !1;
                return !0
            };
            e.renderJsonML = function(e, t) {
                t = t || {}, t.root = t.root || !1;
                var n = [];
                if (t.root) n.push(u(e));
                else
                    for (e.shift(), !e.length || "object" != typeof e[0] || e[0] instanceof Array || e.shift(); e.length;) n.push(u(e.shift()));
                return n.join("\n\n")
            }
        }(function() {
            return t
        }())
    }, function(e, t, n) {
        (function(e, r) {
            function i(e, n) {
                var r = {
                    seen: [],
                    stylize: o
                };
                return arguments.length >= 3 && (r.depth = arguments[2]), arguments.length >= 4 && (r.colors = arguments[3]), h(n) ? r.showHidden = n : n && t._extend(r, n), x(r.showHidden) && (r.showHidden = !1), x(r.depth) && (r.depth = 2), x(r.colors) && (r.colors = !1), x(r.customInspect) && (r.customInspect = !0), r.colors && (r.stylize = a), l(r, e, r.depth)
            }

            function a(e, t) {
                var n = i.styles[t];
                return n ? "[" + i.colors[n][0] + "m" + e + "[" + i.colors[n][1] + "m" : e
            }

            function o(e, t) {
                return e
            }

            function s(e) {
                var t = {};
                return e.forEach(function(e, n) {
                    t[e] = !0
                }), t
            }

            function l(e, n, r) {
                if (e.customInspect && n && O(n.inspect) && n.inspect !== t.inspect && (!n.constructor || n.constructor.prototype !== n)) {
                    var i = n.inspect(r, e);
                    return b(i) || (i = l(e, i, r)), i
                }
                var a = c(e, n);
                if (a) return a;
                var o = Object.keys(n),
                    h = s(o);
                if (e.showHidden && (o = Object.getOwnPropertyNames(n)), T(n) && (o.indexOf("message") >= 0 || o.indexOf("description") >= 0)) return u(n);
                if (0 === o.length) {
                    if (O(n)) {
                        var g = n.name ? ": " + n.name : "";
                        return e.stylize("[Function" + g + "]", "special")
                    }
                    if (k(n)) return e.stylize(RegExp.prototype.toString.call(n), "regexp");
                    if (S(n)) return e.stylize(Date.prototype.toString.call(n), "date");
                    if (T(n)) return u(n)
                }
                var m = "",
                    v = !1,
                    y = ["{", "}"];
                if (_(n) && (v = !0, y = ["[", "]"]), O(n)) {
                    var x = n.name ? ": " + n.name : "";
                    m = " [Function" + x + "]"
                }
                if (k(n) && (m = " " + RegExp.prototype.toString.call(n)), S(n) && (m = " " + Date.prototype.toUTCString.call(n)), T(n) && (m = " " + u(n)), 0 === o.length && (!v || 0 == n.length)) return y[0] + m + y[1];
                if (r < 0) return k(n) ? e.stylize(RegExp.prototype.toString.call(n), "regexp") : e.stylize("[Object]", "special");
                e.seen.push(n);
                var w;
                return w = v ? d(e, n, r, h, o) : o.map(function(t) {
                    return p(e, n, r, h, t, v)
                }), e.seen.pop(), f(w, m, y)
            }

            function c(e, t) {
                if (x(t)) return e.stylize("undefined", "undefined");
                if (b(t)) {
                    var n = "'" + JSON.stringify(t).replace(/^"|"$/g, "").replace(/'/g, "\\'").replace(/\\"/g, '"') + "'";
                    return e.stylize(n, "string")
                }
                return v(t) ? e.stylize("" + t, "number") : h(t) ? e.stylize("" + t, "boolean") : g(t) ? e.stylize("null", "null") : void 0
            }

            function u(e) {
                return "[" + Error.prototype.toString.call(e) + "]"
            }

            function d(e, t, n, r, i) {
                for (var a = [], o = 0, s = t.length; o < s; ++o) $(t, String(o)) ? a.push(p(e, t, n, r, String(o), !0)) : a.push("");
                return i.forEach(function(i) {
                    i.match(/^\d+$/) || a.push(p(e, t, n, r, i, !0))
                }), a
            }

            function p(e, t, n, r, i, a) {
                var o, s, c;
                if (c = Object.getOwnPropertyDescriptor(t, i) || {
                        value: t[i]
                    }, c.get ? s = c.set ? e.stylize("[Getter/Setter]", "special") : e.stylize("[Getter]", "special") : c.set && (s = e.stylize("[Setter]", "special")), $(r, i) || (o = "[" + i + "]"), s || (e.seen.indexOf(c.value) < 0 ? (s = g(n) ? l(e, c.value, null) : l(e, c.value, n - 1), s.indexOf("\n") > -1 && (s = a ? s.split("\n").map(function(e) {
                        return "  " + e
                    }).join("\n").substr(2) : "\n" + s.split("\n").map(function(e) {
                        return "   " + e
                    }).join("\n"))) : s = e.stylize("[Circular]", "special")), x(o)) {
                    if (a && i.match(/^\d+$/)) return s;
                    o = JSON.stringify("" + i), o.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/) ? (o = o.substr(1, o.length - 2), o = e.stylize(o, "name")) : (o = o.replace(/'/g, "\\'").replace(/\\"/g, '"').replace(/(^"|"$)/g, "'"), o = e.stylize(o, "string"))
                }
                return o + ": " + s
            }

            function f(e, t, n) {
                var r = 0,
                    i = e.reduce(function(e, t) {
                        return r++, t.indexOf("\n") >= 0 && r++, e + t.replace(/\u001b\[\d\d?m/g, "").length + 1
                    }, 0);
                return i > 60 ? n[0] + ("" === t ? "" : t + "\n ") + " " + e.join(",\n  ") + " " + n[1] : n[0] + t + " " + e.join(", ") + " " + n[1]
            }

            function _(e) {
                return Array.isArray(e)
            }

            function h(e) {
                return "boolean" == typeof e
            }

            function g(e) {
                return null === e
            }

            function m(e) {
                return null == e
            }

            function v(e) {
                return "number" == typeof e
            }

            function b(e) {
                return "string" == typeof e
            }

            function y(e) {
                return "symbol" == typeof e
            }

            function x(e) {
                return void 0 === e
            }

            function k(e) {
                return w(e) && "[object RegExp]" === E(e)
            }

            function w(e) {
                return "object" == typeof e && null !== e
            }

            function S(e) {
                return w(e) && "[object Date]" === E(e)
            }

            function T(e) {
                return w(e) && ("[object Error]" === E(e) || e instanceof Error)
            }

            function O(e) {
                return "function" == typeof e
            }

            function j(e) {
                return null === e || "boolean" == typeof e || "number" == typeof e || "string" == typeof e || "symbol" == typeof e || "undefined" == typeof e
            }

            function E(e) {
                return Object.prototype.toString.call(e)
            }

            function C(e) {
                return e < 10 ? "0" + e.toString(10) : e.toString(10)
            }

            function I() {
                var e = new Date,
                    t = [C(e.getHours()), C(e.getMinutes()), C(e.getSeconds())].join(":");
                return [e.getDate(), q[e.getMonth()], t].join(" ")
            }

            function $(e, t) {
                return Object.prototype.hasOwnProperty.call(e, t)
            }
            var N = /%[sdj%]/g;
            t.format = function(e) {
                if (!b(e)) {
                    for (var t = [], n = 0; n < arguments.length; n++) t.push(i(arguments[n]));
                    return t.join(" ")
                }
                for (var n = 1, r = arguments, a = r.length, o = String(e).replace(N, function(e) {
                        if ("%%" === e) return "%";
                        if (n >= a) return e;
                        switch (e) {
                            case "%s":
                                return String(r[n++]);
                            case "%d":
                                return Number(r[n++]);
                            case "%j":
                                try {
                                    return JSON.stringify(r[n++])
                                } catch (e) {
                                    return "[Circular]"
                                }
                            default:
                                return e
                        }
                    }), s = r[n]; n < a; s = r[++n]) o += g(s) || !w(s) ? " " + s : " " + i(s);
                return o
            }, t.deprecate = function(n, i) {
                function a() {
                    if (!o) {
                        if (r.throwDeprecation) throw new Error(i);
                        r.traceDeprecation ? console.trace(i) : console.error(i), o = !0
                    }
                    return n.apply(this, arguments)
                }
                if (x(e.process)) return function() {
                    return t.deprecate(n, i).apply(this, arguments)
                };
                if (r.noDeprecation === !0) return n;
                var o = !1;
                return a
            };
            var z, M = {};
            t.debuglog = function(e) {
                if (x(z) && (z = r.env.NODE_DEBUG || ""), e = e.toUpperCase(), !M[e])
                    if (new RegExp("\\b" + e + "\\b", "i").test(z)) {
                        var n = r.pid;
                        M[e] = function() {
                            var r = t.format.apply(t, arguments);
                            console.error("%s %d: %s", e, n, r)
                        }
                    } else M[e] = function() {};
                return M[e]
            }, t.inspect = i, i.colors = {
                bold: [1, 22],
                italic: [3, 23],
                underline: [4, 24],
                inverse: [7, 27],
                white: [37, 39],
                grey: [90, 39],
                black: [30, 39],
                blue: [34, 39],
                cyan: [36, 39],
                green: [32, 39],
                magenta: [35, 39],
                red: [31, 39],
                yellow: [33, 39]
            }, i.styles = {
                special: "cyan",
                number: "yellow",
                boolean: "yellow",
                undefined: "grey",
                null: "bold",
                string: "green",
                date: "magenta",
                regexp: "red"
            }, t.isArray = _, t.isBoolean = h, t.isNull = g, t.isNullOrUndefined = m, t.isNumber = v, t.isString = b, t.isSymbol = y, t.isUndefined = x, t.isRegExp = k, t.isObject = w, t.isDate = S, t.isError = T, t.isFunction = O, t.isPrimitive = j, t.isBuffer = n(23);
            var q = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            t.log = function() {
                console.log("%s - %s", I(), t.format.apply(t, arguments))
            }, t.inherits = n(24), t._extend = function(e, t) {
                if (!t || !w(t)) return e;
                for (var n = Object.keys(t), r = n.length; r--;) e[n[r]] = t[n[r]];
                return e
            }
        }).call(t, function() {
            return this
        }(), n(22))
    }, function(e, t) {
        function n() {
            throw new Error("setTimeout has not been defined")
        }

        function r() {
            throw new Error("clearTimeout has not been defined")
        }

        function i(e) {
            if (u === setTimeout) return setTimeout(e, 0);
            if ((u === n || !u) && setTimeout) return u = setTimeout, setTimeout(e, 0);
            try {
                return u(e, 0)
            } catch (t) {
                try {
                    return u.call(null, e, 0)
                } catch (t) {
                    return u.call(this, e, 0)
                }
            }
        }

        function a(e) {
            if (d === clearTimeout) return clearTimeout(e);
            if ((d === r || !d) && clearTimeout) return d = clearTimeout, clearTimeout(e);
            try {
                return d(e)
            } catch (t) {
                try {
                    return d.call(null, e)
                } catch (t) {
                    return d.call(this, e)
                }
            }
        }

        function o() {
            h && f && (h = !1, f.length ? _ = f.concat(_) : g = -1, _.length && s())
        }

        function s() {
            if (!h) {
                var e = i(o);
                h = !0;
                for (var t = _.length; t;) {
                    for (f = _, _ = []; ++g < t;) f && f[g].run();
                    g = -1, t = _.length
                }
                f = null, h = !1, a(e)
            }
        }

        function l(e, t) {
            this.fun = e, this.array = t
        }

        function c() {}
        var u, d, p = e.exports = {};
        ! function() {
            try {
                u = "function" == typeof setTimeout ? setTimeout : n
            } catch (e) {
                u = n
            }
            try {
                d = "function" == typeof clearTimeout ? clearTimeout : r
            } catch (e) {
                d = r
            }
        }();
        var f, _ = [],
            h = !1,
            g = -1;
        p.nextTick = function(e) {
            var t = new Array(arguments.length - 1);
            if (arguments.length > 1)
                for (var n = 1; n < arguments.length; n++) t[n - 1] = arguments[n];
            _.push(new l(e, t)), 1 !== _.length || h || i(s)
        }, l.prototype.run = function() {
            this.fun.apply(null, this.array)
        }, p.title = "browser", p.browser = !0, p.env = {}, p.argv = [], p.version = "", p.versions = {}, p.on = c, p.addListener = c, p.once = c, p.off = c, p.removeListener = c, p.removeAllListeners = c, p.emit = c, p.prependListener = c, p.prependOnceListener = c, p.listeners = function(e) {
            return []
        }, p.binding = function(e) {
            throw new Error("process.binding is not supported")
        }, p.cwd = function() {
            return "/"
        }, p.chdir = function(e) {
            throw new Error("process.chdir is not supported")
        }, p.umask = function() {
            return 0
        }
    }, function(e, t) {
        e.exports = function(e) {
            return e && "object" == typeof e && "function" == typeof e.copy && "function" == typeof e.fill && "function" == typeof e.readUInt8
        }
    }, function(e, t) {
        "function" == typeof Object.create ? e.exports = function(e, t) {
            e.super_ = t, e.prototype = Object.create(t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            })
        } : e.exports = function(e, t) {
            e.super_ = t;
            var n = function() {};
            n.prototype = t.prototype, e.prototype = new n, e.prototype.constructor = e
        }
    }])
});
/*! Aplura Code Framework  '''                         Written by  Aplura, LLC                         Copyright (C) 2017-2018 Aplura, ,LLC                         This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.                         This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.                         You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. ''' */
define("asa_z_appconfig_authorize", ["splunkjs/mvc", "jquery", "underscore", "splunkjs/mvc/utils", "backbone", "contrib/text"], function(e, t, n, i, a, o) {
    return function(e) {
        function t(i) {
            if (n[i]) return n[i].exports;
            var a = n[i] = {
                exports: {},
                id: i,
                loaded: !1
            };
            return e[i].call(a.exports, a, a.exports, t), a.loaded = !0, a.exports
        }
        var n = {};
        return t.m = e, t.c = n, t.p = "", t(0)
    }([function(e, t, n) {
        var i, a;
        i = [n(2), n(1), n(3), n(4), n(5), n(10)], a = function(e, t, i, a, o, s) {
            return t.fullExtend({
                defaults: {
                    mi_name: "ga"
                },
                initialize: function() {
                    this.constructor.__super__.initialize.apply(this, arguments), this.$el = i(this.el);
                    var t = this;
                    t.set({
                        _template_form: n(25)
                    }), this._service = e.createService();
                    var a = i("#app_config_modify_container");
                    this._input_spec_exists(t, this.get("mi_name"), function(e) {
                        a.append(e.get("_template_form")), i("#authorize_search_btn").on("click", function(t) {
                            e._submit_authorize_form(t, e)
                        }), i("#authorize_reset_btn").on("click", function(e) {
                            location.reload()
                        })
                    })
                },
                _submit_authorize_form: function(e, t) {
                    e.preventDefault();
                    var n = {};
                    a.each(i("#form_authorize_splunk").find("input"), function(e) {
                        n[e.id] = i("#" + e.id).val()
                    });
                    var o = "authMsg",
                        s = n.authorize_domain,
                        r = n.authorize_clientid,
                        l = n.authorize_clientsecret,
                        d = {
                            domain: s,
                            clientid: r,
                            clientsecret: l,
                            authtoken: "",
                            step: "one"
                        },
                        c = n.authorize_authtoken;
                    if ("undefined" == typeof s || s.length < 1) return void i("#" + o).html("Please enter a Domain");
                    if ("undefined" == typeof r || r.length < 1) return void i("#" + o).html("Please enter a Client ID");
                    if ("undefined" == typeof l || l.length < 1) return void i("#" + o).html("Please enter a Client Secret");
                    if ("undefined" == typeof c || c.length < 1) console.log("No Auth Token");
                    else {
                        if (d.step = "two", c.length < 1) return void i("#" + o).html("Must provide Auth Token");
                        d.authtoken = c
                    }
                    this._service.get("/services/gmail_authorize", d).done(function(e) {
                        var t = JSON.parse(e);
                        console.log({
                            "myData return": t
                        });
                        var n = JSON.parse(t.entry[0].content);
                        "launch_url" === n.step ? (window.open(n.url, "_blank"), i("#authorize_search_btn .btn").html("Authorize Step 2"), i("#base_tokens").hide(), i("#auth_token_div").show()) : "end_of_discussion" === n.step ? console.log(n) : (i("#auth_token_div").hide(), i("#authorize_search_btn .btn").html("Done")), i("#" + o).html(n.msg)
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(e, t, n) {
        var i, a;
        i = [n(2), n(6), n(3), n(4), n(5)], a = function(e, t, i, a, o) {
            return function(e) {
                "use strict";
                e.fullExtend = function(t, n) {
                    var i = e.extend.call(this, t, n);
                    if (i.prototype._super = this.prototype, t.defaults)
                        for (var a in this.prototype.defaults) i.prototype.defaults[a] || (i.prototype.defaults[a] = this.prototype.defaults[a]);
                    return i
                }
            }(t.Model), t.Model.extend({
                defaults: {
                    owner: "nobody",
                    is_input: !1,
                    supports_proxy: !1,
                    supports_credential: !1,
                    app: o.getCurrentApp(),
                    TemplateSettings: {
                        interpolate: /\{\{(.+?)\}\}/g
                    },
                    reset_timeout: 5e3,
                    button_container: "button_container",
                    tab_container: "tabs",
                    tab_content_container: "tab_content_container",
                    msg_box: "msg_box"
                },
                getCurrentApp: o.getCurrentApp,
                initialize: function() {
                    t.Model.prototype.initialize.apply(this, arguments), this.service = e.createService({
                        owner: this.get("owner"),
                        app: this.get("app")
                    }), this.$el = i(this.el), this.set({
                        _template_base_modal: n(7),
                        _template_base_tab_content: n(8),
                        _template_base_item_content: n(9)
                    }), this._generate_guids(), this._check_base_eventtype()
                },
                _check_base_eventtype: function() {
                    null === this.get("base_eventtype") || void 0 === this.get("base_eventtype") ? console.log({
                        eventtype: this.get("base_eventtype"),
                        message: "not_found"
                    }) : this._display_base_eventtype()
                },
                _set_documentation: function(e, t) {
                    i(".documentation_box dl").append("<dt>" + e + "</dt><dd>" + t + "</dd>")
                },
                _display_base_eventtype: function() {
                    var e = this,
                        t = "#application_configuration_base_eventtype";
                    this._get_eventtype(this.get("base_eventtype"), function(n) {
                        var a = JSON.parse(n),
                            o = a.entry[0].content.search;
                        i(t).val(o), i(t).data("evt_name", e.get("base_eventtype"))
                    }), i("#app_config_base_eventtype_button").on("click", function(n) {
                        n.preventDefault();
                        var a = i(t).data();
                        e._update_eventtype(a.evt_name, i(t).val())
                    }), i("#app_config_base_eventtype").css("display", "inline-block")
                },
                _get_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        i = this;
                    this.service.request(n, "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        i.display_error(i.get("msg_box"), t.messages[0].text)
                    }).done(function(e) {
                        t(e)
                    })
                },
                _update_eventtype: function(e, t) {
                    var n = this._build_service_url("saved/eventtypes/" + encodeURIComponent(e)),
                        a = this;
                    this.service.request(n, "POST", null, null, i.param({
                        search: t
                    }), {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        var t = JSON.parse(e.responseText);
                        a.display_error(a.get("msg_box"), t.messages[0].text)
                    }).done(function(t) {
                        a.display_message(a.get("msg_box"), e + " updated.")
                    })
                },
                render: function() {
                    console.log("inside base")
                },
                _build_service_url: function(e) {
                    return "/servicesNS/" + encodeURIComponent(this.get("owner")) + "/" + encodeURIComponent(this.get("app")) + "/" + e.replace("%app%", this.get("app"))
                },
                create_modal: function(e) {
                    return a.template(a.template(this.get("_template_base_modal"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings"))
                },
                bind_modal: function(e) {
                    var t = 'form[name="' + e.modal_id + '_configuration"]';
                    i(t).on("submit", function(t) {
                        t.preventDefault(), e.on_submit(e.that, this)
                    }), i("#" + e.modal_id + "_save_button").on("click", function(e) {
                        e.preventDefault(), i(t).submit()
                    })
                },
                _generic_done_request: function(e) {
                    console.log("_generic_done_request not implemented")
                },
                _generic_error_request: function(e, t) {
                    console.log(JSON.parse(t.responseText)), this.display_error(e, JSON.stringify(JSON.parse(t.responseText).messages[0].text).replace("\n", "").replace(/[\n\\]*/gi, ""))
                },
                guid: function() {
                    function e() {
                        return Math.floor(65536 * (1 + Math.random())).toString(16).substring(1)
                    }
                    return e() + e() + "-" + e() + "-" + e() + "-" + e() + "-" + e() + e() + e()
                },
                create_credential: function(e) {
                    var t = this._build_service_url("storage/passwords"),
                        n = {
                            realm: e.realm || this.get("app"),
                            name: encodeURIComponent(e.user),
                            password: encodeURIComponent(e.password)
                        };
                    this.service.request(t, "POST", null, null, i.param(n), {
                        "Content-Type": "text/plain"
                    }, null).error(e.error || function(e) {
                        console.log("callback not set. call returned error.")
                    }).done(e.done || function(e) {
                        console.log("callback not set. call returned done")
                    })
                },
                update_credential: function(e) {
                    console.log("update_credential not implemented")
                },
                get_credential: function(e) {
                    var t = e.realm,
                        n = e.done,
                        i = e.t;
                    i.service.request(i._build_service_url("storage/passwords"), "GET", {
                        search: t
                    }).error(function(e) {
                        i._generic_error_request(i.get("msg_box"), e)
                    }).done(function(e) {
                        n(JSON.parse(e))
                    })
                },
                _input_spec_exists: function(e, t, n) {
                    console.log({
                        mvc: e.service
                    }), e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(t)), "GET", null, null, null, {
                        "Content-Type": "application/json"
                    }, null).error(function(e) {
                        console.log("data/inputs/" + t + " doesn't exist, or errored. Removing Tab.")
                    }).done(function(t) {
                        n(e)
                    })
                },
                sanatize: function(e) {
                    return decodeURIComponent(i.trim(e)).replace(/([\\\/!@#$%\^&\*\(\):\s])/g, "_sc_").replace(/\./g, "_")
                },
                _convert_new_data: function(e) {
                    return {}
                },
                prep_data: function(e) {
                    for (var t = {}, n = 0; n < e.length; n++) {
                        var i = e[n].name,
                            a = e[n].value;
                        t[i] = a
                    }
                    return t
                },
                display_error: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-flag" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.addClass("ui-state-error") : null;
                    console.log(o), this.reset_message(e)
                },
                display_message: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-check" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                display_warning: function(e, t) {
                    var n = i("#" + e).html(t.length > 0 ? '<span class="ui-icon ui-icon-alert" style="float:left; margin-right:.3em"></span><strong>' + a.escape(t) + "</strong>" : ""),
                        o = t.length > 0 ? n.removeClass("ui-state-error").addClass("ui-state-highlight") : null;
                    console.log(o), this.reset_message(e)
                },
                reset_message: function(e) {
                    setTimeout(function() {
                        var t = i("#" + e).html("");
                        t.removeClass("ui-state-error").removeClass("ui-state-highlight")
                    }, this.get("reset_timeout"))
                },
                add_button: function(e, t) {
                    var n = this.guid(),
                        o = this,
                        s = '<button type="button" id="' + a.escape(n) + '" class="btn btn-primary">' + e + "</button>";
                    return t === !0 ? i("#" + this.get("tab_content_id")).prepend(s) : i("#" + this.get("button_container")).append(s), i("#" + n).on("click", function(e) {
                        a.each(o.get("modal_defaults"), function(e, t) {
                            o._set_modal_default(o.get("modal_id"), t, e)
                        }), i("#" + o.get("modal_id")).modal("show")
                    }), n
                },
                _hide_tabs: function() {
                    i(".tab_content").hide()
                },
                _show_tab_content: function(e) {
                    i("#" + e).show()
                },
                add_tab: function(e) {
                    e.tab_id = this.guid(), e.hasOwnProperty("tab_content") || (e.tab_content = ""), e.hasOwnProperty("tab_xref") || (e.tab_xref = "");
                    var t = this,
                        n = a.template(t.get("_template_base_tab_content"), e, t.get("TemplateSettings"));
                    return i("#" + this.get("tab_content_container")).append(n), i("#" + this.get("tab_container")).append('<li title="' + a.escape(e.tab_xref) + ' Tab"><a  href="#' + a.escape(e.tab_xref) + '" class="toggle-tab" data-toggle="tab" data-elements="' + a.escape(e.tab_id) + '">' + a.escape(e.text) + "</li>"), i(".toggle-tab").on("click", function(e) {
                        t._hide_tabs(), i(this).css("class", "active");
                        var n = i(this).data();
                        t._show_tab_content(n.elements)
                    }), t._hide_tabs(), i(".toggle-tab").first().trigger("click"), e.tab_id
                },
                _set_modal_default: function(e, t, n) {
                    i("#" + e + ' input[name="' + t + '"]').val(n)
                },
                create_item: function(e) {
                    return e.hasOwnProperty("item_id") || (e.item_id = this.guid()), e.hasOwnProperty("item_form") || (e.item_form = ""), e.hasOwnProperty("item_disabled_state") || (e.item_disabled_state = !0), e.hasOwnProperty("enable_reload") || (e.enable_reload = !1), e.hasOwnProperty("item_name") || (e.item_name = "undefined"), e.hasOwnProperty("data_options") || (e.data_options = {}), e.hasOwnProperty("item_state_color") || (e.item_state_color = e.item_disabled_state ? "#d6563c" : "#65a637"), e.hasOwnProperty("item_state_icon") || (e.item_state_icon = e.item_disabled_state ? " icon-minus-circle " : " icon-check-circle"), {
                        html: a.template(a.template(this.get("_template_base_item_content"), e, this.get("TemplateSettings")), e, this.get("TemplateSettings")),
                        id: e.item_id
                    }
                },
                _display_item: function(e, t) {
                    t.supports_proxy = "true" == a.escape(e.get("supports_proxy")), t.is_input = "true" == a.escape(e.get("is_input"));
                    var n = "#" + e.get("tab_content_id") + "_display_container",
                        o = e.create_item(t);
                    i(n).append(o.html), i("#" + o.id + "_deletable").on("click", function(t) {
                        e._delete_item(e, this)
                    }), i("#" + o.id + "_enablement").on("click", function(t) {
                        e._toggle_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] input:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), i('form[name="' + o.id + '_configuration"] select:enabled').on("change", function(t) {
                        e._edit_item(e, this)
                    }), t.supports_proxy && e.get_proxies({
                        s: t.items.proxy_name,
                        i: o.id + "_configuration"
                    }), t.is_input && e.get_indexes({
                        s: t.items.index,
                        i: o.id
                    }), t.supports_credential && e.get_credentials({
                        s: t.items.report_credential_realm,
                        i: o.id
                    })
                },
                _delete_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data();
                    return !!confirm("Really delete Item " + a.stanza_name + "?") && void e.service.del(a.remove_link).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(t) {
                        i("." + n + "_container").fadeOut().remove(), e.display_message(e.get("msg_box"), "Deleted the Item")
                    })
                },
                _generate_guids: function() {
                    this.set({
                        modal_id: this.guid(),
                        modal_form_id: this.guid()
                    })
                },
                _generate_modal: function(e) {
                    var t = this;
                    e.proxy_list = e.that.get_proxies("not_configured"), e.supports_proxy = t.get("supports_proxy"), e.is_input = t.get("is_input"), e.modal_id = t.get("modal_id"), e.test_class = e.test_class || "";
                    var n = t.create_modal(e);
                    i("body").append(n), t.bind_modal(e), e.supports_proxy && t.get_proxies({
                        s: "not_configured",
                        i: t.get("modal_id")
                    }), e.is_input && t.get_indexes({
                        s: "main",
                        i: t.get("modal_id")
                    })
                },
                _validate_object: function(e, t) {
                    switch (e) {
                        case "interval":
                            return !(t.length < 1 || !t.match(/^\d+$/) || t < 60)
                    }
                    return !0
                },
                _validate_form: function(e) {},
                _validate_interval: function(e) {
                    var t = e.length > 1,
                        n = !!e.match(/^\d+$/),
                        i = e >= 60;
                    return t || n || i
                },
                _validate_proxy_name: function(e) {
                    return !(e.length < 1 || "N/A" == e)
                },
                _validate_mod_input_name: function(e) {
                    if (e.length < 1) return !1;
                    var t = e.match(/[0-9a-zA-Z_]+/)[0];
                    return !(t.length < e.length) && this.get("mi_name") + "://" + e
                },
                _toggle_item: function(e, t) {
                    var n = i(t).data().name,
                        a = i("#" + n + "_data_configuration").data(),
                        o = a.disabled,
                        s = !o,
                        r = s ? "#d6563c" : "#65a637",
                        l = s ? " icon-minus-circle " : " icon-check-circle",
                        d = a.edit_link,
                        c = e.get("msg_box");
                    e.service.request(d, "POST", null, null, i.param({
                        disabled: s.toString()
                    }), {
                        "Content-Type": "text/plain"
                    }, null).error(function(t) {
                        e._generic_error_request(e.get("msg_box"), t)
                    }).done(function(o) {
                        e.service.request(e._build_service_url("data/inputs/" + encodeURIComponent(a.mi_name) + "/_reload"), "GET").done(function(a) {
                            i(t).css("color", r), i(t).removeClass("icon-minus-circle").removeClass("icon-check-circle").addClass(l), i("#" + n + "_data_configuration").data({
                                disabled: s
                            }), e.display_message(c, "Disabled: " + s), i("#" + n + "_enablement").text(s ? " Disabled" : " Enabled")
                        }).error(function(t) {
                            e._generic_error_request(e.get("msg_box"), t)
                        })
                    })
                },
                _combine_multibox: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = n[0].name,
                        s = a.id,
                        r = n[0].id,
                        l = n.val(),
                        d = !1;
                    o.includes("[]") && (l = [], i(i("#" + s + '_configuration input:checkbox:checked[name="' + o + '"]')).each(function(e) {
                        l[e] = i(this).val()
                    }), i("#" + s + '_configuration input[id="' + o.replace("[]", "") + '"]').each(function(e) {
                        var t = i(this).val();
                        t.length > 1 && (l[l.length] = i(this).val())
                    }), l = l.join(","), r = o.replace("[]", ""), d = !0);
                    var c = "#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]';
                    if (i(c).length > 0 && !d) {
                        var u = [];
                        i(i("#" + s + '_configuration input:checkbox:checked[name="' + r + '[]"]')).each(function(e) {
                            u[e] = i(this).val()
                        }), u[u.length] = l, l = u.join(","), d = !0
                    }
                    return {
                        f: r,
                        v: l
                    }
                },
                _reload_config: function(e, t) {
                    var n = e._build_service_url(t.endpoint + "/_reload");
                    t.endpoint.indexOf("inputs") > -1 && (n = e._build_service_url("data/inputs/" + encodeURIComponent(e.get("mi_name")) + "/_reload")), e.service.request(n, "GET").error(function(n) {
                        e._generic_error_request(t.msg, n)
                    }).done(function(n) {
                        t.done(e, n)
                    })
                },
                _create_item: function(e, t) {
                    e.service.request(e._build_service_url(t.endpoint), "POST", null, null, i.param(t.data)).error(function(t) {
                        e._generic_error_request(e.get("modal_id") + "_msg_box", t)
                    }).done(function(n) {
                        e._reload_config(e, {
                            endpoint: t.endpoint,
                            msg: e.get("modal_id") + "_msg_box",
                            done: function(e, i) {
                                t.done(e, n)
                            }
                        })
                    })
                },
                _edit_item: function(e, t) {
                    var n = i(t),
                        a = n.data(),
                        o = a.id,
                        s = n[0].id,
                        r = i("#" + o + "_data_configuration").data(),
                        l = e._combine_multibox(e, t);
                    s = l.f;
                    var d = l.v;
                    if ("must_have" in a && (s = a.must_have, d = i("#" + o + '_configuration input[id="' + a.must_have + '"]').val()), d = d.replace(/,+$/, ""), "update_type" in a && "checkbox" === a.update_type && (d = n.is(":checked") ? "true" : "false"), e._validate_object(s, d)) switch (a.update_type || (a.update_type = "inputs"), a.update_type) {
                        case "up":
                            e.update_credential({
                                i: o,
                                t: e,
                                ed: a,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        case "token":
                            console.log("future implementation");
                            break;
                        case "checkbox":
                            console.log({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            }), e.update_property({
                                e: a.config_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            });
                            break;
                        default:
                            e.update_property({
                                e: a.update_type,
                                i: o,
                                t: e,
                                d: r,
                                f: s,
                                v: d
                            })
                    } else e.display_error(o + "_msg", s + " failed validation.")
                },
                update_property: function(e) {
                    var t = e.t,
                        n = e.d.stanza_name,
                        a = e.f,
                        o = e.v,
                        s = e.i,
                        r = t._build_service_url("properties/" + e.e + "/" + encodeURIComponent(n) + "/" + a),
                        l = i.param({
                            value: o
                        });
                    t.service.request(r, "POST", null, null, l).error(function(e) {
                        t._generic_error_request(t.get("msg_box"), e)
                    }).done(function(n) {
                        t.display_message(s + "_msg", a + " updated successfully."), t._reload_config(t, {
                            endpoint: "inputs",
                            mi_name: e.d.mi_name,
                            msg: "msg_box",
                            done: function(e, t) {
                                e.display_message("msg_box", "Input Configuration Reloaded")
                            }
                        })
                    })
                },
                get_proxies: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [{
                            selected: "not_configured" == n ? "selected" : "",
                            name: "None",
                            value: "not_configured"
                        }],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-proxy"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + ' select[name="proxy_name"]');
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                },
                get_credentials: function(e) {
                    var t = e.i,
                        n = [],
                        o = this;
                    this.service.request(this._build_service_url("storage/passwords"), "GET").error(function(e) {
                        o._generic_error_request(o.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].content;
                            n.push({
                                username: r.username,
                                realm: r.realm,
                                value: o.guid()
                            })
                        }
                        var l = i("#" + t + "_list_credentials");
                        l.empty(), a.each(n, function(e) {
                            l.append("<option id='" + a.escape(e.realm) + "' data-realm='" + a.escape(e.realm) + "' data-user='" + a.escape(e.username) + "' value='" + a.escape(e.realm) + "'>" + a.escape(e.realm) + "</option>")
                        })
                    })
                },
                get_indexes: function(e) {
                    var t = e.i,
                        n = e.s,
                        o = [],
                        s = this;
                    this.service.request(this._build_service_url("configs/conf-indexes"), "GET").error(function(e) {
                        s._generic_error_request(s.get("msg_box"), e)
                    }).done(function(e) {
                        e = JSON.parse(e);
                        for (var s = 0; s < e.entry.length; s++) {
                            var r = e.entry[s].name;
                            o.push({
                                selected: r == n ? " selected " : "",
                                name: r,
                                value: r
                            })
                        }
                        var l = i("#" + t + "_list_indexes");
                        l.empty(), a.each(o, function(e) {
                            l.append("<option " + a.escape(e.selected) + " value='" + a.escape(e.value) + "'>" + a.escape(e.name) + "</option>")
                        })
                    })
                }
            })
        }.apply(t, i), !(void 0 !== a && (e.exports = a))
    }, function(t, n) {
        t.exports = e
    }, function(e, n) {
        e.exports = t
    }, function(e, t) {
        e.exports = n
    }, function(e, t) {
        e.exports = i
    }, function(e, t) {
        e.exports = a
    }, function(e, t) {
        e.exports = '<div class="modal fade" id="{{modal_id}}">\n    <div class="modal-dialog" role="document">\n        <div class="modal-content">\n            <div class="modal-header">\n                <button type="button" class="close" data-dismiss="modal" aria-label="Close">\n                    <span aria-hidden="true">X</span>\n                </button>\n                <h4 class="modal-title">{{modal_name}}</h4>\n            </div>\n            <div class="modal-body modal-body-scrolling form form-horizontal" style="display: block;">\n                <div id="{{modal_id}}_msg_box" class=" ui-corner-all msg_box" style="padding:5px;margin:5px;"/>\n                <form id="{{modal_id}}_configuration" name="{{modal_id}}_configuration"\n                      class="splunk-formatter-section" section-label="{{modal_name}}">\n                    {{modal_form_html}}\n                    <% if ( is_input ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Interval (s)</label>\n                        <div class="controls controls-block">\n                            <input type="text" id="interval" name="interval" required="required"/>\n                            <span class="help-block ">Can only contain numbers, and a minimum as specified for the app.</span>\n                        </div>\n                    </div>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Index</label>\n                        <div class="controls controls-block">\n                            <input type="text" list="{{modal_id}}_list_indexes" class="input-medium index"\n                                   data-id="{{modal_id}}" id="index" name="index"/>\n                            <datalist id="{{modal_id}}_list_indexes"></datalist>\n                            <span class="help-block ">Specify an index. If blank the default index will be used.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                    <% if ( supports_proxy ) { %>\n                    <div class="control-group shared-controls-controlgroup control-group-default">\n                        <label class="control-label">Proxy Name</label>\n                        <div class="controls controls-block">\n                            <select data-id="{{modal_id}}" id="proxy_name" name="proxy_name">\n                            </select>\n                            <span class="help-block ">The stanza name for a configured proxy.</span>\n                        </div>\n                    </div>\n                    <% } %>\n                </form>\n            </div>\n            <div class="modal-footer">\n                <button type="button" data-test_class="{{test_class}}_close" class="btn btn-secondary"\n                        data-dismiss="modal">Close</button>\n                <button type="button" data-test_class="{{test_class}}" class="btn btn-primary"\n                        id="{{modal_id}}_save_button">Save Changes</button>\n            </div>\n        </div><!-- /.modal-content -->\n    </div><!-- /.modal-dialog -->\n</div><!-- /.modal -->'
    }, function(e, t) {
        e.exports = '<div id="{{tab_id}}" class="tab_content">\n    <div class="tab_content_container control-group tab_content_height">\n        <div id="{{tab_id}}_display_container" class="controls controls-fill existing_container">\n            {{tab_content}}\n        </div>\n    </div>\n</div>'
    }, function(e, t) {
        e.exports = '<div class="item_container control-group  {{item_id}}_container">\n    <div id="{{item_id}}_msg" class=" ui-corner-all" style="padding:5px;margin:5px;"></div>\n    <div class="clickable delete" style="height:auto">\n        <a href="#" title="Delete item" id="{{item_id}}_deletable" data-name="{{item_id}}"\n           class="icon-trash btn-pill btn-square shared-jobstatus-buttons-printbutton "\n           style="float:right;font-size:22px;">\n        </a>\n    </div>\n    <% if ( enable_reload ) { %>\n    <div class="clickable_mod_input enablement" id="{{item_id}}" data-name="{{item_id}}"\n         data-disabled="{{item_disabled_state}}"  style="height:auto">\n        <a title="Disable / Enable the Input" href="#" id="{{item_id}}_enablement"\n           class="{{item_state_icon}} btn-pill" data-name="{{item_id}}"\n           data-disabled="{{item_disabled_state}}" style="float:right; color: {{item_state_color}}; font-size:12px;">\n            <% if ( !item_disabled_state ) { %>Enabled<% } else {%>Disabled<% } %>\n        </a>\n    </div>\n    <% } %>\n    <h3>{{item_name}}</h3>\n    <form id="{{item_id}}_configuration" name="{{item_id}}_configuration" class="splunk-formatter-section">\n        {{item_form}}\n        <% if ( is_input ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Interval (s):</label>\n            <input type="text" class="input-medium interval" data-id="{{item_id}}" id="interval"\n                   value="{{items.interval}}"/>\n        </div>\n        <div class="controls controls-fill">\n            <label class="control-label">Index:</label>\n            <input type="text" list="{{item_id}}_list_indexes" class="input-medium index" data-id="{{item_id}}"\n                   id="index" name="index" value="{{items.index}}"/>\n            <datalist id="{{item_id}}_list_indexes"></datalist>\n        </div>\n        <% } %>\n        <% if ( supports_proxy ) { %>\n        <div class="controls controls-fill">\n            <label class="control-label">Proxy Name:</label>\n            <select class="input-medium proxy_name" data-id="{{item_id}}" id="proxy_name" name="proxy_name">\n            </select>\n        </div>\n        <% } %>\n        <input type="hidden" id="{{item_id}}_data_configuration"\n        <% _.each( data_options, function (r) { %>\n        data-{{r.id}}="{{r.value}}"\n        <% }); %>\n        />\n    </form>\n</div>'
    }, function(e, t) {
        e.exports = o
    }, , , , , , , , , , , , , , , function(e, t) {
        e.exports = '<div><h3 id="authMsg" style="color:red"></h3>\n    <div id="row1" class="dashboard-row dashboard-row1">\n        <div id="panel1" class="dashboard-cell">\n            <div class="dashboard-panel clearfix" style="min-height: 128px;">\n                <div class="panel-element-row inline-panel">\n                    <form id="form_authorize_splunk" name="form_authorize_splunk" onsubmit="return false;">\n                        <div class="fieldset">\n                            <div id="base_tokens">\n                                <div class="input">\n                                    <label>Google Apps Domain</label>\n                                    <input class="input input-text" id="authorize_domain" type="text"/>\n                                </div>\n                                <div class="input">\n                                    <label>Client ID</label>\n                                    <input type="text" class="input input-text" id="authorize_clientid"/>\n                                </div>\n                                <div class="input">\n                                    <label>Client Secret</label>\n                                    <input type="text" class="input input-text" id="authorize_clientsecret"/>\n                                </div>\n                            </div>\n                            <div class="input" id="auth_token_div" style="display:none;">\n                                <label>Authorization Token</label>\n                                <input type="text" class="input input-text" id="authorize_authtoken"/>\n                            </div>\n                            <div class="form-submit" id="authorize_search_btn">\n                                <button class="btn btn-primary submit">Authorize Step 1</button>\n                            </div>\n                            <div class="form-submit" id="authorize_reset_btn">\n                                <button class="btn btn-primary submit">Reset</button>\n                            </div>\n                        </div>\n                    </form>\n                </div>\n            </div>\n        </div>\n        <div id="panel2" class="dashboard-cell">\n            <div class="dashboard-panel clearfix" style="min-height: 128px;">\n                <div class="panel-element-row inline-panel">\n                    <div id="element2" class="dashboard-element single" style="width: 100%">\n                        <div class="panel-head">\n                            <h3>Instructions</h3>\n                        </div>\n                        <div class="panel-body">\n                            <blockquote>This setup page authorizes the GMail Audit TA to communicate with the necessary APIs to enable and retrieve email auditing. This app is designed with multiple G Suite domains in mind.\n                                Before setting up any Data Inputs, you must authorize the app access to your Domain via\n                                OAuth.\n                            </blockquote>\n                            <blockquote><strong>It is HIGHLY recommended to setup a separate Splunk specific Super Admin\n                                user within Google Apps.</strong></blockquote>\n                            <blockquote>\n                                <ul>\n                                    <li>Enter your Google Apps Domain into the first box above</li>\n                                    <li>You will need the Client ID and Client Secret from a project you create at <a\n                                            target="_blank" href="https://console.developers.google.com/">https://console.developers.google.com/</a>.\n                                        Once there go through <strong>API Project -> APIs & Auth -> Credentials. Create Client\n                                            ID ->  Other</strong>. Copy the Client ID and Client Secret into the  boxes above.\n                                    </li>\n                                    <li>While you are at the Developer Console, make sure you enable the <strong>Admin\n                                        SDK</strong> API, the <strong>GMail</strong> API and the <strong>Audit</strong> API. If you do not, this will not work.\n                                    </li>\n                                    <li>These are the Current Scopes requested: <ul>\n <li>https://www.googleapis.com/auth/gmail.modify</li>\n<li>https://www.googleapis.com/auth/admin.directory.user</li>\n <li>https://apps-apis.google.com/a/feeds/compliance/audit/</li></ul></li>\n                                    <li>Once you have entered those items, click <b>Authorize Step 1.</b> A Pop-up will open, so make\n                                        sure\n                                        you unblock it.\n                                    </li>\n                                    <li>Click the Accept button (after any login actions into your domain).</li>\n                                    <li>The form will return a key, copy that key, and paste it into Authorization Token\n                                        box above. Click Authorize Step 2.\n                                    </li>\n                                </ul>\n                                This writes a file to the $APP_HOME/local folder with the oauth information. This\n                                completes the steps for OAuth2 for the Google Apps APIs.\n                                You can now go the Inputs menu to configure inputs to start consuming data for this domain.\n                            </blockquote>\n                        </div>\n                    </div>\n                </div>\n            </div>\n        </div>\n <div class="dashboard-row" style="float: left;"><h3 class="dashboard-row">Once the initial configuration is complete, click the Save button to start using the application. </h3> <button type="button" id="app_config_button" class="dashboard-row btn btn-primary">Save</button> </div>\n</div>'
    }])
});
