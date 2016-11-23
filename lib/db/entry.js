


function load(req, res, next) {
    if (req._entry) {
        return next();
    }

    return req.get(req.bucket, req.key, function (err, val, meta) {
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
