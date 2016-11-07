/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2016, Les Technologies Alesium, Inc.
 */

var util = require('util');

var Validator = require('../lib/schema/validator');



///--- API

function OrganizationalUnit() {
    Validator.call(this, {
        name: 'organizationalunit',
        required: {
            ou: 1
        },
        strict: true
    });
}
util.inherits(OrganizationalUnit, Validator);



///--- Exports

module.exports = {
    createInstance: function createInstance() {
        return new OrganizationalUnit();
    }
};
