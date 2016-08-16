module.exports = function auth(scopes) {
    return function (req, res, next) {
        if (req.user && Array.isArray(req.user.scopes) && Array.isArray(scopes)) {
            req.user.scopes.find(predicate) ? next() : next(new Error('Unauthorized'));
        } else {
            next(new Error('Unauthorized'));
        }

        function predicate(scope) {
            return scopes.indexOf(scope) > -1;
        }
    }
};