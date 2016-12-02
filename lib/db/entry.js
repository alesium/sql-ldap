/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

var assert = require('assert');
var util = require('util');

var ldap = require('ldapjs');
var vasync = require('vasync');

var UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function load(req, res, next) {
    if (req._entry) {
        return next();
    }

    return req.get(req.key, function (err, val, meta) {
        if (err) {
            return next(err);
        }

        req._entry = _subUser(val.value);
        req._meta = {
            etag: val._etag
        }; // pick up etag
        return next();
    });
}


///--- Exports

module.exports = {
    load: load

};
