/*
 asa_init.js
 '''
 Written by Kyle Smith for Aplura, LLC
 Copyright (C) 2016 Aplura, ,LLC

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 '''
 */
require([
    "jquery",
    "asa_config",
    "splunkjs/ready!",
    "splunkjs/mvc/simplexml/ready!" ,"asa_mi_ga","asa_mi_ga_ss","asa_mi_ga_bigquery", 
 "asa_proxy", 
 "asa_credential", 
 "asa_readme", 
 "asa_z_appconfig_authorize"
], function ($,
             configManager,
             mvc,
             ignored , asa_mi_ga, asa_mi_ga_ss, asa_mi_ga_bigquery,
    asa_proxy,
    asa_credential,
    asa_readme,
    asa_z_appconfig_authorize
) {
    var configMan = new configManager();
    var miMan_ga = new asa_mi_ga();var miMan_ga_ss = new asa_mi_ga_ss();var miMan_ga_bigquery = new asa_mi_ga_bigquery();
    var appConfig_asa_proxy = new asa_proxy(); 
    var appConfig_asa_credential = new asa_credential(); 
    var appConfig_asa_readme = new asa_readme(); 
    var appConfig_asa_z_appconfig_authorize = new asa_z_appconfig_authorize(); 



    var tryfunc = function() {
    if (!$(".clickable_mod_input.enablement a, .clickable.delete a").size()) {
      window.requestAnimationFrame(tryfunc);
    }else {
      $(".clickable_mod_input.enablement a, .clickable.delete a").tooltip({position: {collision: "flip"}});
     }
  };
    tryfunc();
});