t = undefined;
var sjcl = {
    cipher: {},
    hash: {},
    keyexchange: {},
    mode: {},
    misc: {},
    codec: {},
    exception: {
        corrupt: function(b) {
            this.toString = function() {
                return "CORRUPT: " + this.message
            }
            ;
            this.message = b
        },
        invalid: function(b) {
            this.toString = function() {
                return "INVALID: " + this.message
            }
            ;
            this.message = b
        },
        bug: function(b) {
            this.toString = function() {
                return "BUG: " + this.message
            }
            ;
            this.message = b
        },
        notReady: function(b) {
            this.toString = function() {
                return "NOT READY: " + this.message
            }
            ;
            this.message = b
        }
    }
};
"undefined" !== typeof module && module.exports && (module.exports = sjcl);
"function" === typeof define && define([], function() {
    return sjcl
});
sjcl.cipher.aes = function(j) {
    this.k[0][0][0] || this.D();
    var i, p, o, n, m = this.k[0][4], l = this.k[1];
    i = j.length;
    var k = 1;
    4 !== i && (6 !== i && 8 !== i) && q(new sjcl.exception.invalid("invalid aes key size"));
    this.b = [o = j.slice(0), n = []];
    for (j = i; j < 4 * i + 28; j++) {
        p = o[j - 1];
        if (0 === j % i || 8 === i && 4 === j % i) {
            p = m[p >>> 24] << 24 ^ m[p >> 16 & 255] << 16 ^ m[p >> 8 & 255] << 8 ^ m[p & 255],
            0 === j % i && (p = p << 8 ^ p >>> 24 ^ k << 24,
            k = k << 1 ^ 283 * (k >> 7))
        }
        o[j] = o[j - i] ^ p
    }
    for (i = 0; j; i++,
    j--) {
        p = o[i & 3 ? j : j - 4],
        n[i] = 4 >= j || 4 > i ? p : l[0][m[p >>> 24]] ^ l[1][m[p >> 16 & 255]] ^ l[2][m[p >> 8 & 255]] ^ l[3][m[p & 255]]
    }
}
;

function y(ab, aa, Z) {
    4 !== aa.length && q(new sjcl.exception.invalid("invalid aes block size"));
    var Y = ab.b[Z]
      , X = aa[0] ^ Y[0]
      , W = aa[Z ? 3 : 1] ^ Y[1]
      , V = aa[2] ^ Y[2];
    aa = aa[Z ? 1 : 3] ^ Y[3];
    var U, S, T, Q = Y.length / 4 - 2, R, P = 4, N = [0, 0, 0, 0];
    U = ab.k[Z];
    ab = U[0];
    var O = U[1]
      , o = U[2]
      , j = U[3]
      , i = U[4];
    for (R = 0; R < Q; R++) {
        U = ab[X >>> 24] ^ O[W >> 16 & 255] ^ o[V >> 8 & 255] ^ j[aa & 255] ^ Y[P],
        S = ab[W >>> 24] ^ O[V >> 16 & 255] ^ o[aa >> 8 & 255] ^ j[X & 255] ^ Y[P + 1],
        T = ab[V >>> 24] ^ O[aa >> 16 & 255] ^ o[X >> 8 & 255] ^ j[W & 255] ^ Y[P + 2],
        aa = ab[aa >>> 24] ^ O[X >> 16 & 255] ^ o[W >> 8 & 255] ^ j[V & 255] ^ Y[P + 3],
        P += 4,
        X = U,
        W = S,
        V = T
    }
    for (R = 0; 4 > R; R++) {
        N[Z ? 3 & -R : R] = i[X >>> 24] << 24 ^ i[W >> 16 & 255] << 16 ^ i[V >> 8 & 255] << 8 ^ i[aa & 255] ^ Y[P++],
        U = X,
        X = W,
        W = V,
        V = aa,
        aa = U
    }
    return N
}
sjcl.cipher.aes.prototype = {
    encrypt: function(b) {
        return y(this, b, 0)
    },
    decrypt: function(b) {
        return y(this, b, 1)
    },
    k: [[[], [], [], [], []], [[], [], [], [], []]],
    D: function() {
        var R = this.k[0], Q = this.k[1], P = R[4], O = Q[4], N, x, w, v = [], r = [], s, j, o, i;
        for (N = 0; 256 > N; N++) {
            r[(v[N] = N << 1 ^ 283 * (N >> 7)) ^ N] = N
        }
        for (x = w = 0; !P[x]; x ^= s || 1,
        w = r[w] || 1) {
            o = w ^ w << 1 ^ w << 2 ^ w << 3 ^ w << 4;
            o = o >> 8 ^ o & 255 ^ 99;
            P[x] = o;
            O[o] = x;
            j = v[N = v[s = v[x]]];
            i = 16843009 * j ^ 65537 * N ^ 257 * s ^ 16843008 * x;
            j = 257 * v[o] ^ 16843008 * o;
            for (N = 0; 4 > N; N++) {
                R[N][x] = j = j << 24 ^ j >>> 8,
                Q[N][o] = i = i << 24 ^ i >>> 8
            }
        }
        for (N = 0; 5 > N; N++) {
            R[N] = R[N].slice(0),
            Q[N] = Q[N].slice(0)
        }
    }
};

sjcl.bitArray = {
    bitSlice: function(e, d, f) {
        e = sjcl.bitArray.P(e.slice(d / 32), 32 - (d & 31)).slice(1);
        return f === t ? e : sjcl.bitArray.clamp(e, f - d)
    },
    extract: function(f, e, h) {
        var g = Math.floor(-e - h & 31);
        return ((e + h - 1 ^ e) & -32 ? f[e / 32 | 0] << 32 - g ^ f[e / 32 + 1 | 0] >>> g : f[e / 32 | 0] >>> g) & (1 << h) - 1
    },
    concat: function(f, e) {
        if (0 === f.length || 0 === e.length) {
            return f.concat(e)
        }
        var h = f[f.length - 1]
          , g = sjcl.bitArray.getPartial(h);
        return 32 === g ? f.concat(e) : sjcl.bitArray.P(e, g, h | 0, f.slice(0, f.length - 1))
    },
    bitLength: function(d) {
        var c = d.length;
        return 0 === c ? 0 : 32 * (c - 1) + sjcl.bitArray.getPartial(d[c - 1])
    },
    clamp: function(e, d) {
        if (32 * e.length < d) {
            return e
        }
        e = e.slice(0, Math.ceil(d / 32));
        var f = e.length;
        d &= 31;
        0 < f && d && (e[f - 1] = sjcl.bitArray.partial(d, e[f - 1] & 2147483648 >> d - 1, 1));
        return e
    },
    partial: function(e, d, f) {
        return 32 === e ? d : (f ? d | 0 : d << 32 - e) + 1099511627776 * e
    },
    getPartial: function(b) {
        return Math.round(b / 1099511627776) || 32
    },
    equal: function(f, e) {
        if (sjcl.bitArray.bitLength(f) !== sjcl.bitArray.bitLength(e)) {
            return u
        }
        var h = 0, g;
        for (g = 0; g < f.length; g++) {
            h |= f[g] ^ e[g]
        }
        return 0 === h
    },
    P: function(g, f, j, i) {
        var h;
        h = 0;
        for (i === t && (i = []); 32 <= f; f -= 32) {
            i.push(j),
            j = 0
        }
        if (0 === f) {
            return i.concat(g)
        }
        for (h = 0; h < g.length; h++) {
            i.push(j | g[h] >>> f),
            j = g[h] << 32 - f
        }
        h = g.length ? g[g.length - 1] : 0;
        g = sjcl.bitArray.getPartial(h);
        i.push(sjcl.bitArray.partial(f + g & 31, 32 < f + g ? j : i.pop(), 1));
        return i
    },
    l: function(d, c) {
        return [d[0] ^ c[0], d[1] ^ c[1], d[2] ^ c[2], d[3] ^ c[3]]
    },
    byteswapM: function(e) {
        var d, f;
        for (d = 0; d < e.length; ++d) {
            f = e[d],
            e[d] = f >>> 24 | f >>> 8 & 65280 | (f & 65280) << 8 | f << 24
        }
        return e
    }
};
sjcl.codec.utf8String = {
    fromBits: function(g) {
        var f = "", j = sjcl.bitArray.bitLength(g), i, h;
        for (i = 0; i < j / 8; i++) {
            0 === (i & 3) && (h = g[i / 4]),
            f += String.fromCharCode(h >>> 24),
            h <<= 8
        }
        return decodeURIComponent(escape(f))
    },
    toBits: function(f) {
        f = unescape(encodeURIComponent(f));
        var e = [], h, g = 0;
        for (h = 0; h < f.length; h++) {
            g = g << 8 | f.charCodeAt(h),
            3 === (h & 3) && (e.push(g),
            g = 0)
        }
        h & 3 && e.push(sjcl.bitArray.partial(8 * (h & 3), g));
        return e
    }
};
sjcl.codec.hex = {
    fromBits: function(e) {
        var d = "", f;
        for (f = 0; f < e.length; f++) {
            d += ((e[f] | 0) + 263882790666240).toString(16).substr(4)
        }
        return d.substr(0, sjcl.bitArray.bitLength(e) / 4)
    },
    toBits: function(f) {
        var e, h = [], g;
        f = f.replace(/\s|0x/g, "");
        g = f.length;
        f += "00000000";
        for (e = 0; e < f.length; e += 8) {
            h.push(parseInt(f.substr(e, 8), 16) ^ 0)
        }
        return sjcl.bitArray.clamp(h, 4 * g)
    }
};
sjcl.codec.base64 = {
    J: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    fromBits: function(j, i, p) {
        var o = ""
          , n = 0
          , m = sjcl.codec.base64.J
          , l = 0
          , k = sjcl.bitArray.bitLength(j);
        p && (m = m.substr(0, 62) + "-_");
        for (p = 0; 6 * o.length < k; ) {
            o += m.charAt((l ^ j[p] >>> n) >>> 26),
            6 > n ? (l = j[p] << 6 - n,
            n += 26,
            p++) : (l <<= 6,
            n -= 6)
        }
        for (; o.length & 3 && !i; ) {
            o += "="
        }
        return o
    },
    toBits: function(j, i) {
        j = j.replace(/\s|=/g, "");
        var p = [], o, n = 0, m = sjcl.codec.base64.J, l = 0, k;
        i && (m = m.substr(0, 62) + "-_");
        for (o = 0; o < j.length; o++) {
            k = m.indexOf(j.charAt(o)),
            0 > k && q(new sjcl.exception.invalid("this isn't base64!")),
            26 < n ? (n -= 26,
            p.push(l ^ k >>> n),
            l = k << 32 - n) : (n += 6,
            l ^= k << 32 - n)
        }
        n & 56 && p.push(sjcl.bitArray.partial(n & 56, l, 1));
        return p
    }
};
sjcl.codec.base64url = {
    fromBits: function(b) {
        return sjcl.codec.base64.fromBits(b, 1, 1)
    },
    toBits: function(b) {
        return sjcl.codec.base64.toBits(b, 1)
    }
};
sjcl.hash.sha256 = function(b) {
    this.b[0] || this.D();
    b ? (this.r = b.r.slice(0),
    this.o = b.o.slice(0),
    this.h = b.h) : this.reset()
}
;
sjcl.hash.sha256.hash = function(b) {
    return (new sjcl.hash.sha256).update(b).finalize()
}
;

function z(V, U) {
    var T, S, R, Q = U.slice(0), P = V.r, O = V.b, x = P[0], N = P[1], o = P[2], w = P[3], j = P[4], X = P[5], i = P[6], W = P[7];
    for (T = 0; 64 > T; T++) {
        16 > T ? S = Q[T] : (S = Q[T + 1 & 15],
        R = Q[T + 14 & 15],
        S = Q[T & 15] = (S >>> 7 ^ S >>> 18 ^ S >>> 3 ^ S << 25 ^ S << 14) + (R >>> 17 ^ R >>> 19 ^ R >>> 10 ^ R << 15 ^ R << 13) + Q[T & 15] + Q[T + 9 & 15] | 0),
        S = S + W + (j >>> 6 ^ j >>> 11 ^ j >>> 25 ^ j << 26 ^ j << 21 ^ j << 7) + (i ^ j & (X ^ i)) + O[T],
        W = i,
        i = X,
        X = j,
        j = w + S | 0,
        w = o,
        o = N,
        N = x,
        x = S + (N & o ^ w & (N ^ o)) + (N >>> 2 ^ N >>> 13 ^ N >>> 22 ^ N << 30 ^ N << 19 ^ N << 10) | 0
    }
    P[0] = P[0] + x | 0;
    P[1] = P[1] + N | 0;
    P[2] = P[2] + o | 0;
    P[3] = P[3] + w | 0;
    P[4] = P[4] + j | 0;
    P[5] = P[5] + X | 0;
    P[6] = P[6] + i | 0;
    P[7] = P[7] + W | 0
}
sjcl.hash.sha256.prototype = {
    blockSize: 512,
    reset: function() {
        this.r = this.N.slice(0);
        this.o = [];
        this.h = 0;
        return this
    },
    update: function(e) {
        "string" === typeof e && (e = sjcl.codec.utf8String.toBits(e));
        var d, f = this.o = sjcl.bitArray.concat(this.o, e);
        d = this.h;
        e = this.h = d + sjcl.bitArray.bitLength(e);
        for (d = 512 + d & -512; d <= e; d += 512) {
            z(this, f.splice(0, 16))
        }
        return this
    },
    finalize: function() {
        var e, d = this.o, f = this.r, d = sjcl.bitArray.concat(d, [sjcl.bitArray.partial(1, 1)]);
        for (e = d.length + 2; e & 15; e++) {
            d.push(0)
        }
        d.push(Math.floor(this.h / 4294967296));
        for (d.push(this.h | 0); d.length; ) {
            z(this, d.splice(0, 16))
        }
        this.reset();
        return f
    },
    N: [],
    b: [],
    D: function() {
        function f(b) {
            return 4294967296 * (b - Math.floor(b)) | 0
        }
        var e = 0, h = 2, g;
        f: for (; 64 > e; h++) {
            for (g = 2; g * g <= h; g++) {
                if (0 === h % g) {
                    continue f
                }
            }
            8 > e && (this.N[e] = f(Math.pow(h, 0.5)));
            this.b[e] = f(Math.pow(h, 1 / 3));
            e++
        }
    }
};

sjcl.mode.ccm = {
    name: "ccm",
    encrypt: function(w, v, s, r, p) {
        var o, n = v.slice(0), m = sjcl.bitArray, i = m.bitLength(s) / 8, j = m.bitLength(n) / 8;
        p = p || 64;
        r = r || [];
        7 > i && q(new sjcl.exception.invalid("ccm: iv must be at least 7 bytes"));
        for (o = 2; 4 > o && j >>> 8 * o; o++) {}
        o < 15 - i && (o = 15 - i);
        s = m.clamp(s, 8 * (15 - o));
        v = sjcl.mode.ccm.L(w, v, s, r, p, o);
        n = sjcl.mode.ccm.p(w, n, s, v, p, o);
        return m.concat(n.data, n.tag)
    },
    decrypt: function(w, v, s, r, p) {
        p = p || 64;
        r = r || [];
        var o = sjcl.bitArray
          , n = o.bitLength(s) / 8
          , m = o.bitLength(v)
          , i = o.clamp(v, m - p)
          , j = o.bitSlice(v, m - p)
          , m = (m - p) / 8;
        7 > n && q(new sjcl.exception.invalid("ccm: iv must be at least 7 bytes"));
        for (v = 2; 4 > v && m >>> 8 * v; v++) {}
        v < 15 - n && (v = 15 - n);
        s = o.clamp(s, 8 * (15 - v));
        i = sjcl.mode.ccm.p(w, i, s, j, p, v);
        w = sjcl.mode.ccm.L(w, i.data, s, r, p, v);
        o.equal(i.tag, w) || q(new sjcl.exception.corrupt("ccm: tag doesn't match"));
        return i.data
    },
    L: function(s, r, p, o, n, m) {
        var k = []
          , j = sjcl.bitArray
          , i = j.l;
        n /= 8;
        (n % 2 || 4 > n || 16 < n) && q(new sjcl.exception.invalid("ccm: invalid tag length"));
        (4294967295 < o.length || 4294967295 < r.length) && q(new sjcl.exception.bug("ccm: can't deal with 4GiB or more data"));
        m = [j.partial(8, (o.length ? 64 : 0) | n - 2 << 2 | m - 1)];
        m = j.concat(m, p);
        m[3] |= j.bitLength(r) / 8;
        m = s.encrypt(m);
        if (o.length) {
            p = j.bitLength(o) / 8;
            65279 >= p ? k = [j.partial(16, p)] : 4294967295 >= p && (k = j.concat([j.partial(16, 65534)], [p]));
            k = j.concat(k, o);
            for (o = 0; o < k.length; o += 4) {
                m = s.encrypt(i(m, k.slice(o, o + 4).concat([0, 0, 0])))
            }
        }
        for (o = 0; o < r.length; o += 4) {
            m = s.encrypt(i(m, r.slice(o, o + 4).concat([0, 0, 0])))
        }
        return j.clamp(m, 8 * n)
    },
    p: function(w, v, s, r, p, o) {
        var n, m = sjcl.bitArray;
        n = m.l;
        var i = v.length
          , j = m.bitLength(v);
        s = m.concat([m.partial(8, o - 1)], s).concat([0, 0, 0]).slice(0, 4);
        r = m.bitSlice(n(r, w.encrypt(s)), 0, p);
        if (!i) {
            return {
                tag: r,
                data: []
            }
        }
        for (n = 0; n < i; n += 4) {
            s[3]++,
            p = w.encrypt(s),
            v[n] ^= p[0],
            v[n + 1] ^= p[1],
            v[n + 2] ^= p[2],
            v[n + 3] ^= p[3]
        }
        return {
            tag: r,
            data: m.clamp(v, j)
        }
    }
};
sjcl.mode.ocb2 = {
    name: "ocb2",
    encrypt: function(R, Q, P, O, N, x) {
        128 !== sjcl.bitArray.bitLength(P) && q(new sjcl.exception.invalid("ocb iv must be 128 bits"));
        var w, v = sjcl.mode.ocb2.H, r = sjcl.bitArray, s = r.l, j = [0, 0, 0, 0];
        P = v(R.encrypt(P));
        var o, i = [];
        O = O || [];
        N = N || 64;
        for (w = 0; w + 4 < Q.length; w += 4) {
            o = Q.slice(w, w + 4),
            j = s(j, o),
            i = i.concat(s(P, R.encrypt(s(P, o)))),
            P = v(P)
        }
        o = Q.slice(w);
        Q = r.bitLength(o);
        w = R.encrypt(s(P, [0, 0, 0, Q]));
        o = r.clamp(s(o.concat([0, 0, 0]), w), Q);
        j = s(j, s(o.concat([0, 0, 0]), w));
        j = R.encrypt(s(j, s(P, v(P))));
        O.length && (j = s(j, x ? O : sjcl.mode.ocb2.pmac(R, O)));
        return i.concat(r.concat(o, r.clamp(j, N)))
    },
    decrypt: function(U, T, S, R, Q, P) {
        128 !== sjcl.bitArray.bitLength(S) && q(new sjcl.exception.invalid("ocb iv must be 128 bits"));
        Q = Q || 64;
        var O = sjcl.mode.ocb2.H, N = sjcl.bitArray, w = N.l, x = [0, 0, 0, 0], o = O(U.encrypt(S)), v, j, V = sjcl.bitArray.bitLength(T) - Q, i = [];
        R = R || [];
        for (S = 0; S + 4 < V / 32; S += 4) {
            v = w(o, U.decrypt(w(o, T.slice(S, S + 4)))),
            x = w(x, v),
            i = i.concat(v),
            o = O(o)
        }
        j = V - 32 * S;
        v = U.encrypt(w(o, [0, 0, 0, j]));
        v = w(v, N.clamp(T.slice(S), j).concat([0, 0, 0]));
        x = w(x, v);
        x = U.encrypt(w(x, w(o, O(o))));
        R.length && (x = w(x, P ? R : sjcl.mode.ocb2.pmac(U, R)));
        N.equal(N.clamp(x, Q), N.bitSlice(T, V)) || q(new sjcl.exception.corrupt("ocb: tag doesn't match"));
        return i.concat(N.clamp(v, j))
    },
    pmac: function(j, i) {
        var p, o = sjcl.mode.ocb2.H, n = sjcl.bitArray, m = n.l, l = [0, 0, 0, 0], k = j.encrypt([0, 0, 0, 0]), k = m(k, o(o(k)));
        for (p = 0; p + 4 < i.length; p += 4) {
            k = o(k),
            l = m(l, j.encrypt(m(k, i.slice(p, p + 4))))
        }
        p = i.slice(p);
        128 > n.bitLength(p) && (k = m(k, o(k)),
        p = n.concat(p, [-2147483648, 0, 0, 0]));
        l = m(l, p);
        return j.encrypt(m(o(m(k, o(k))), l))
    },
    H: function(b) {
        return [b[0] << 1 ^ b[1] >>> 31, b[1] << 1 ^ b[2] >>> 31, b[2] << 1 ^ b[3] >>> 31, b[3] << 1 ^ 135 * (b[0] >>> 31)]
    }
};
sjcl.mode.gcm = {
    name: "gcm",
    encrypt: function(h, g, l, k, j) {
        var i = g.slice(0);
        g = sjcl.bitArray;
        k = k || [];
        h = sjcl.mode.gcm.p(!0, h, i, k, l, j || 128);
        return g.concat(h.data, h.tag)
    },
    decrypt: function(j, i, p, o, n) {
        var m = i.slice(0)
          , l = sjcl.bitArray
          , k = l.bitLength(m);
        n = n || 128;
        o = o || [];
        n <= k ? (i = l.bitSlice(m, k - n),
        m = l.bitSlice(m, 0, k - n)) : (i = m,
        m = []);
        j = sjcl.mode.gcm.p(u, j, m, o, p, n);
        l.equal(j.tag, i) || q(new sjcl.exception.corrupt("gcm: tag doesn't match"));
        return j.data
    },
    Z: function(j, i) {
        var p, o, n, m, l, k = sjcl.bitArray.l;
        n = [0, 0, 0, 0];
        m = i.slice(0);
        for (p = 0; 128 > p; p++) {
            (o = 0 !== (j[Math.floor(p / 32)] & 1 << 31 - p % 32)) && (n = k(n, m));
            l = 0 !== (m[3] & 1);
            for (o = 3; 0 < o; o--) {
                m[o] = m[o] >>> 1 | (m[o - 1] & 1) << 31
            }
            m[0] >>>= 1;
            l && (m[0] ^= -520093696)
        }
        return n
    },
    g: function(g, f, j) {
        var i, h = j.length;
        f = f.slice(0);
        for (i = 0; i < h; i += 4) {
            f[0] ^= 4294967295 & j[i],
            f[1] ^= 4294967295 & j[i + 1],
            f[2] ^= 4294967295 & j[i + 2],
            f[3] ^= 4294967295 & j[i + 3],
            f = sjcl.mode.gcm.Z(f, g)
        }
        return f
    },
    p: function(U, T, S, R, Q, P) {
        var O, N, w, x, o, v, j, V, i = sjcl.bitArray;
        v = S.length;
        j = i.bitLength(S);
        V = i.bitLength(R);
        N = i.bitLength(Q);
        O = T.encrypt([0, 0, 0, 0]);
        96 === N ? (Q = Q.slice(0),
        Q = i.concat(Q, [1])) : (Q = sjcl.mode.gcm.g(O, [0, 0, 0, 0], Q),
        Q = sjcl.mode.gcm.g(O, Q, [0, 0, Math.floor(N / 4294967296), N & 4294967295]));
        N = sjcl.mode.gcm.g(O, [0, 0, 0, 0], R);
        o = Q.slice(0);
        R = N.slice(0);
        U || (R = sjcl.mode.gcm.g(O, N, S));
        for (x = 0; x < v; x += 4) {
            o[3]++,
            w = T.encrypt(o),
            S[x] ^= w[0],
            S[x + 1] ^= w[1],
            S[x + 2] ^= w[2],
            S[x + 3] ^= w[3]
        }
        S = i.clamp(S, j);
        U && (R = sjcl.mode.gcm.g(O, N, S));
        U = [Math.floor(V / 4294967296), V & 4294967295, Math.floor(j / 4294967296), j & 4294967295];
        R = sjcl.mode.gcm.g(O, R, U);
        w = T.encrypt(Q);
        R[0] ^= w[0];
        R[1] ^= w[1];
        R[2] ^= w[2];
        R[3] ^= w[3];
        return {
            tag: i.bitSlice(R, 0, P),
            data: S
        }
    }
};
sjcl.misc.hmac = function(g, f) {
    this.M = f = f || sjcl.hash.sha256;
    var j = [[], []], i, h = f.prototype.blockSize / 32;
    this.n = [new f, new f];
    g.length > h && (g = f.hash(g));
    for (i = 0; i < h; i++) {
        j[0][i] = g[i] ^ 909522486,
        j[1][i] = g[i] ^ 1549556828
    }
    this.n[0].update(j[0]);
    this.n[1].update(j[1]);
    this.G = new f(this.n[0])
}
;
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function(b) {
    this.Q && q(new sjcl.exception.invalid("encrypt on already updated hmac called!"));
    this.update(b);
    return this.digest(b)
}
;
sjcl.misc.hmac.prototype.reset = function() {
    this.G = new this.M(this.n[0]);
    this.Q = u
}
;
sjcl.misc.hmac.prototype.update = function(b) {
    this.Q = !0;
    this.G.update(b)
}
;
sjcl.misc.hmac.prototype.digest = function() {
    var b = this.G.finalize()
      , b = (new this.M(this.n[1])).update(b).finalize();
    this.reset();
    return b
}
;
sjcl.misc.pbkdf2 = function(N, x, w, v, s) {
    w = w || 1000;
    (0 > v || 0 > w) && q(sjcl.exception.invalid("invalid params to pbkdf2"));
    "string" === typeof N && (N = sjcl.codec.utf8String.toBits(N));
    "string" === typeof x && (x = sjcl.codec.utf8String.toBits(x));
    s = s || sjcl.misc.hmac;
    N = new s(N);
    var r, p, o, j, m = [], i = sjcl.bitArray;
    for (j = 1; 32 * m.length < (v || 1); j++) {
        s = r = N.encrypt(i.concat(x, [j]));
        for (p = 1; p < w; p++) {
            r = N.encrypt(r);
            for (o = 0; o < r.length; o++) {
                s[o] ^= r[o]
            }
        }
        m = m.concat(s)
    }
    v && (m = i.clamp(m, v));
    return m
}
;
sjcl.prng = function(b) {
    this.c = [new sjcl.hash.sha256];
    this.i = [0];
    this.F = 0;
    this.s = {};
    this.C = 0;
    this.K = {};
    this.O = this.d = this.j = this.W = 0;
    this.b = [0, 0, 0, 0, 0, 0, 0, 0];
    this.f = [0, 0, 0, 0];
    this.A = undefined;
    this.B = b;
    this.q = false;
    this.w = {
        progress: {},
        seeded: {}
    };
    this.m = this.V = 0;
    this.t = 1;
    this.u = 2;
    this.S = 65536;
    this.I = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
    this.T = 30000;
    this.R = 80
}
;
function q(b) {
    throw b
}

function A(b) {
    b.b = B(b).concat(B(b));
    b.A = new sjcl.cipher.aes(b.b)
}
function B(d) {
    for (var c = 0; 4 > c && !(d.f[c] = d.f[c] + 1 | 0,
    d.f[c]); c++) {}
    return d.A.encrypt(d.f)
}
function D(d, c) {
    return function() {
        c.apply(d, arguments)
    }
}
sjcl.prng.prototype = {
    randomWords: function(i, h) {
        var n = [], m;
        m = this.isReady(h);
        var l;
        m === this.m && q(new sjcl.exception.notReady("generator isn't seeded"));
        if (m & this.u) {
            m = !(m & this.t);
            l = [];
            var k = 0, j;
            this.O = l[0] = (new Date).valueOf() + this.T;
            for (j = 0; 16 > j; j++) {
                l.push(4294967296 * Math.random() | 0)
            }
            for (j = 0; j < this.c.length && !(l = l.concat(this.c[j].finalize()),
            k += this.i[j],
            this.i[j] = 0,
            !m && this.F & 1 << j); j++) {}
            this.F >= 1 << this.c.length && (this.c.push(new sjcl.hash.sha256),
            this.i.push(0));
            this.d -= k;
            k > this.j && (this.j = k);
            this.F++;
            this.b = sjcl.hash.sha256.hash(this.b.concat(l));
            this.A = new sjcl.cipher.aes(this.b);
            for (m = 0; 4 > m && !(this.f[m] = this.f[m] + 1 | 0,
            this.f[m]); m++) {}
        }
        for (m = 0; m < i; m += 4) {
            0 === (m + 1) % this.S && A(this),
            l = B(this),
            n.push(l[0], l[1], l[2], l[3])
        }
        A(this);
        return n.slice(0, i)
    },
    setDefaultParanoia: function(d, c) {
        0 === d && "Setting paranoia=0 will ruin your security; use it only for testing" !== c && q("Setting paranoia=0 will ruin your security; use it only for testing");
        this.B = d
    },
    addEntropy: function(s, r, p) {
        p = p || "user";
        var o, n, m = (new Date).valueOf(), k = this.s[p], j = this.isReady(), i = 0;
        o = this.K[p];
        o === t && (o = this.K[p] = this.W++);
        k === t && (k = this.s[p] = 0);
        this.s[p] = (this.s[p] + 1) % this.c.length;
        switch (typeof s) {
        case "number":
            r === t && (r = 1);
            this.c[k].update([o, this.C++, 1, r, m, 1, s | 0]);
            break;
        case "object":
            p = Object.prototype.toString.call(s);
            if ("[object Uint32Array]" === p) {
                n = [];
                for (p = 0; p < s.length; p++) {
                    n.push(s[p])
                }
                s = n
            } else {
                "[object Array]" !== p && (i = 1);
                for (p = 0; p < s.length && !i; p++) {
                    "number" !== typeof s[p] && (i = 1)
                }
            }
            if (!i) {
                if (r === t) {
                    for (p = r = 0; p < s.length; p++) {
                        for (n = s[p]; 0 < n; ) {
                            r++,
                            n >>>= 1
                        }
                    }
                }
                this.c[k].update([o, this.C++, 2, r, m, s.length].concat(s))
            }
            break;
        case "string":
            r === t && (r = s.length);
            this.c[k].update([o, this.C++, 3, r, m, s.length]);
            this.c[k].update(s);
            break;
        default:
            i = 1
        }
        i && q(new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string"));
        this.i[k] += r;
        this.d += r;
        j === this.m && (this.isReady() !== this.m && C("seeded", Math.max(this.j, this.d)),
        C("progress", this.getProgress()))
    },
    isReady: function(b) {
        b = this.I[b !== t ? b : this.B];
        return this.j && this.j >= b ? this.i[0] > this.R && (new Date).valueOf() > this.O ? this.u | this.t : this.t : this.d >= b ? this.u | this.m : this.m
    },
    getProgress: function(b) {
        b = this.I[b ? b : this.B];
        return this.j >= b ? 1 : this.d > b ? 1 : this.d / b
    },
    startCollectors: function() {
        this.q || (this.a = {
            loadTimeCollector: D(this, this.aa),
            mouseCollector: D(this, this.ba),
            keyboardCollector: D(this, this.$),
            accelerometerCollector: D(this, this.U)
        },
        window.addEventListener ? (window.addEventListener("load", this.a.loadTimeCollector, u),
        window.addEventListener("mousemove", this.a.mouseCollector, u),
        window.addEventListener("keypress", this.a.keyboardCollector, u)) : document.attachEvent ? (document.attachEvent("onload", this.a.loadTimeCollector),
        document.attachEvent("onmousemove", this.a.mouseCollector),
        document.attachEvent("keypress", this.a.keyboardCollector)) : q(new sjcl.exception.bug("can't attach event")),
        this.q = !0)
    },
    stopCollectors: function() {
        this.q && (window.removeEventListener ? (window.removeEventListener("load", this.a.loadTimeCollector, u),
        window.removeEventListener("mousemove", this.a.mouseCollector, u),
        window.removeEventListener("keypress", this.a.keyboardCollector, u)) : document.detachEvent && (document.detachEvent("onload", this.a.loadTimeCollector),
        document.detachEvent("onmousemove", this.a.mouseCollector),
        document.detachEvent("keypress", this.a.keyboardCollector)),
        this.q = u)
    },
    addEventListener: function(d, c) {
        this.w[d][this.V++] = c
    },
    removeEventListener: function(h, g) {
        var l, k, j = this.w[h], i = [];
        for (k in j) {
            j.hasOwnProperty(k) && j[k] === g && i.push(k)
        }
        for (l = 0; l < i.length; l++) {
            k = i[l],
            delete j[k]
        }
    },
    $: function() {
        E(1)
    },
    ba: function(f) {
        var e, h;
        try {
            e = f.x || f.clientX || f.offsetX || 0,
            h = f.y || f.clientY || f.offsetY || 0
        } catch (g) {
            h = e = 0
        }
        0 != e && 0 != h && sjcl.random.addEntropy([e, h], 2, "mouse");
        E(0)
    },
    aa: function() {
        E(2)
    },
    U: function(d) {
        d = (d.accelerationIncludingGravity || {}).x || (d.accelerationIncludingGravity || {}).y || (d.accelerationIncludingGravity || {}).z;
        if (window.orientation) {
            var c = window.orientation;
            "number" === typeof c && sjcl.random.addEntropy(c, 1, "accelerometer")
        }
        d && sjcl.random.addEntropy(d, 2, "accelerometer");
        E(0)
    }
};

sjcl.random = new sjcl.prng(6);
a: try {
    var F, G, H, I;
    if (I = "undefined" !== typeof module) {
        var J;
        if (J = module.exports) {
            var K;
            try {
                K = require("crypto")
            } catch (L) {
                K = null
            }
            J = (G = K) && G.randomBytes
        }
        I = J
    }
    if (I) {
        F = G.randomBytes(128),
        F = new Uint32Array((new Uint8Array(F)).buffer),
        sjcl.random.addEntropy(F, 1024, "crypto['randomBytes']")
    } else {
        if ("undefined" !== typeof window && "undefined" !== typeof Uint32Array) {
            H = new Uint32Array(32);
            if (window.crypto && window.crypto.getRandomValues) {
                window.crypto.getRandomValues(H)
            } else {
                if (window.msCrypto && window.msCrypto.getRandomValues) {
                    window.msCrypto.getRandomValues(H)
                } else {
                    break a
                }
            }
            sjcl.random.addEntropy(H, 1024, "crypto['getRandomValues']")
        }
    }
} catch (M) {
    "undefined" !== typeof window && window.console && (console.log("There was an error collecting entropy from the browser:"),
    console.log(M))
}
sjcl.json = {
    defaults: {
        v: 1,
        iter: 1000,
        ks: 128,
        ts: 64,
        mode: "ccm",
        adata: "",
        cipher: "aes"
    },
    Y: function(i, h, n, m) {
        n = n || {};
        m = m || {};
        var l = sjcl.json, k = l.e({
            iv: sjcl.random.randomWords(4, 0)
        }, l.defaults), j;
        l.e(k, n);
        n = k.adata;
        "string" === typeof k.salt && (k.salt = sjcl.codec.base64.toBits(k.salt));
        "string" === typeof k.iv && (k.iv = sjcl.codec.base64.toBits(k.iv));
        (!sjcl.mode[k.mode] || !sjcl.cipher[k.cipher] || "string" === typeof i && 100 >= k.iter || 64 !== k.ts && 96 !== k.ts && 128 !== k.ts || 128 !== k.ks && 192 !== k.ks && 256 !== k.ks || 2 > k.iv.length || 4 < k.iv.length) && q(new sjcl.exception.invalid("json encrypt: invalid parameters"));
        "string" === typeof i ? (j = sjcl.misc.cachedPbkdf2(i, k),
        i = j.key.slice(0, k.ks / 32),
        k.salt = j.salt) : sjcl.ecc && i instanceof sjcl.ecc.elGamal.publicKey && (j = i.kem(),
        k.kemtag = j.tag,
        i = j.key.slice(0, k.ks / 32));
        "string" === typeof h && (h = sjcl.codec.utf8String.toBits(h));
        "string" === typeof n && (n = sjcl.codec.utf8String.toBits(n));
        j = new sjcl.cipher[k.cipher](i);
        l.e(m, k);
        m.key = i;
        k.ct = sjcl.mode[k.mode].encrypt(j, h, k.iv, n, k.ts);
        return k
    },
    encrypt: function(h, g, l, k) {
        var j = sjcl.json
          , i = j.Y.apply(j, arguments);
        return j.encode(i)
    },
    X: function(i, h, n, m) {
        n = n || {};
        m = m || {};
        var l = sjcl.json;
        h = l.e(l.e(l.e({}, l.defaults), h), n, !0);
        var k, j;
        k = h.adata;
        "string" === typeof h.salt && (h.salt = sjcl.codec.base64.toBits(h.salt));
        "string" === typeof h.iv && (h.iv = sjcl.codec.base64.toBits(h.iv));
        (!sjcl.mode[h.mode] || !sjcl.cipher[h.cipher] || "string" === typeof i && 100 >= h.iter || 64 !== h.ts && 96 !== h.ts && 128 !== h.ts || 128 !== h.ks && 192 !== h.ks && 256 !== h.ks || !h.iv || 2 > h.iv.length || 4 < h.iv.length) && q(new sjcl.exception.invalid("json decrypt: invalid parameters"));
        "string" === typeof i ? (j = sjcl.misc.cachedPbkdf2(i, h),
        i = j.key.slice(0, h.ks / 32),
        h.salt = j.salt) : sjcl.ecc && i instanceof sjcl.ecc.elGamal.secretKey && (i = i.unkem(sjcl.codec.base64.toBits(h.kemtag)).slice(0, h.ks / 32));
        "string" === typeof k && (k = sjcl.codec.utf8String.toBits(k));
        j = new sjcl.cipher[h.cipher](i);
        k = sjcl.mode[h.mode].decrypt(j, h.ct, h.iv, k, h.ts);
        l.e(m, h);
        m.key = i;
        return 1 === n.raw ? k : sjcl.codec.utf8String.fromBits(k)
    },
    decrypt: function(g, f, j, i) {
        var h = sjcl.json;
        return h.X(g, h.decode(f), j, i)
    },
    encode: function(f) {
        var e, h = "{", g = "";
        for (e in f) {
            if (f.hasOwnProperty(e)) {
                switch (e.match(/^[a-z0-9]+$/i) || q(new sjcl.exception.invalid("json encode: invalid property name")),
                h += g + '"' + e + '":',
                g = ",",
                typeof f[e]) {
                case "number":
                case "boolean":
                    h += f[e];
                    break;
                case "string":
                    h += '"' + escape(f[e]) + '"';
                    break;
                case "object":
                    h += '"' + sjcl.codec.base64.fromBits(f[e], 0) + '"';
                    break;
                default:
                    q(new sjcl.exception.bug("json encode: unsupported type"))
                }
            }
        }
        return h + "}"
    },
    decode: function(f) {
        f = f.replace(/\s/g, "");
        f.match(/^\{.*\}$/) || q(new sjcl.exception.invalid("json decode: this isn't json!"));
        f = f.replace(/^\{|\}$/g, "").split(/,/);
        var e = {}, h, g;
        for (h = 0; h < f.length; h++) {
            (g = f[h].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i)) || q(new sjcl.exception.invalid("json decode: this isn't json!")),
            e[g[2]] = g[3] ? parseInt(g[3], 10) : g[2].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(g[4]) : unescape(g[4])
        }
        return e
    },
    e: function(f, e, h) {
        f === t && (f = {});
        if (e === t) {
            return f
        }
        for (var g in e) {
            e.hasOwnProperty(g) && (h && (f[g] !== t && f[g] !== e[g]) && q(new sjcl.exception.invalid("required parameter overridden")),
            f[g] = e[g])
        }
        return f
    },
    ea: function(f, e) {
        var h = {}, g;
        for (g in f) {
            f.hasOwnProperty(g) && f[g] !== e[g] && (h[g] = f[g])
        }
        return h
    },
    da: function(f, e) {
        var h = {}, g;
        for (g = 0; g < e.length; g++) {
            f[e[g]] !== t && (h[e[g]] = f[e[g]])
        }
        return h
    }
};
sjcl.encrypt = sjcl.json.encrypt;
sjcl.decrypt = sjcl.json.decrypt;
sjcl.misc.ca = {};
sjcl.misc.cachedPbkdf2 = function(f, e) {
    var h = sjcl.misc.ca, g;
    e = e || {};
    g = e.iter || 1000;
    h = h[f] = h[f] || {};
    g = h[g] = h[g] || {
        firstSalt: e.salt && e.salt.length ? e.salt.slice(0) : sjcl.random.randomWords(2, 0)
    };
    h = e.salt === t ? g.firstSalt : e.salt;
    g[h] = g[h] || sjcl.misc.pbkdf2(f, h, e.iter);
    return {
        key: g[h].slice(0),
        salt: h.slice(0)
    }
}
;
(function(a) {
    var b = a.codec.bytes = a.codec.bytes || {};
    b.fromBits = b.fromBits || function(c) {
        var d = [], g = a.bitArray.bitLength(c), f, e;
        for (f = 0; f < g / 8; f++) {
            if ((f & 3) === 0) {
                e = c[f / 4]
            }
            d.push(e >>> 24);
            e <<= 8
        }
        return d
    }
    ;
    b.toBits = b.toBits || function(c) {
        var d = [], f, e = 0;
        for (f = 0; f < c.length; f++) {
            e = e << 8 | c[f];
            if ((f & 3) === 3) {
                d.push(e);
                e = 0
            }
        }
        if (f & 3) {
            d.push(a.bitArray.partial(8 * (f & 3), e))
        }
        return d
    }
}(sjcl));
sjcl.random.addEntropy((new Date).valueOf(), 0, "loadtime")
sjcl.random.addEntropy([122, 2], 2, "mouse");
function C(g, f) {
    var j, i = sjcl.random.w[g], h = [];
    for (j in i) {
        i.hasOwnProperty(j) && h.push(i[j])
    }
    for (j = 0; j < h.length; j++) {
        h[j](f)
    }
}
module.exports = {sjcl};