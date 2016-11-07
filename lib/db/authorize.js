/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

var ldap = require('ldapjs');

var common = require('./common');



///--- Handlers

function authorize(req, res, next) {
    if (req.type === 'BindRequest') {
        return next();
    }

    var bindDN = req.connection.ldap.bindDN;

    // Leaky abstraction; we assume a config.rootDN was set
    if (bindDN.equals(req.config.rootDN)) {
        return next();
    }

    if (bindDN.equals(req.dn) || bindDN.parentOf(req.dn)) {
        return next();
    }

    return next(new ldap.InsufficientAccessRightsError());

  }



///--- Exports

module.exports = authorize;
