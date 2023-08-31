import * as requests from 'requests';
import { HTTPError } from 'requests.exceptions';
import { JWTError, jwt } from 'jose';
import { ALGORITHMS } from 'jose.constants';
import * as json from 'json';

class AuthLiteClient {
    secret_key: string;
    api_key: string;
    org_id: string | null;
    signed_key: string;
    jwt_encode: (key: string, data: object) => string;
    jwt_decode: (key: string, data: string) => object;

    class TokenCheck {
        access: string;
        refresh: string;
        state: boolean;
    }

    constructor(api_key: string, secret_key: string, org_id?: string) {
        this.jwt_encode = (key, data) => jwt.encode(data, key = key, algorithm = ALGORITHMS.HS256);
        this.jwt_decode = (key, data) => jwt.decode(String(data), key = key, algorithms = ALGORITHMS.HS256);
        this.secret_key = secret_key;
        this.api_key = api_key;
        this.org_id = org_id || null;
        this.signed_key = this.jwt_encode(key = this.secret_key, data = { "api_key": this.api_key });
    }

    generate_url(): string {
        if (this.org_id) return `https://app.trustauthx.com/widget/login/?org_id=${this.org_id}`;
        else throw new Error("must provide org_id");
    }

    generate_edit_user_url(access_token: string, url: string): string {
        let headers = { 'accept': 'application/json' };
        let params = {
            'AccessToken': access_token,
            'api_key': this.api_key,
            'signed_key': this.signed_key,
            'url': url
        };
        let url_ = "https://api.trustauthx.com/api/user/me/settings/";
        let req = requests.Request('GET', url_, params = params, headers = headers).prepare();
        return req.url;
    }

    re_auth(code: string): object {
        let url_ = "https://api.trustauthx.com/api/user/me/widget/re-auth/token";
        let params = {
            "code": code,
            'api_key': this.api_key,
            'signed_key': this.signed_key
        };
        let headers = { "accept": "application/json" };
        let response = requests.get(url_, headers = headers, params = params);
        if (response.status_code == 200) {
            let rtn = this.jwt_decode(this.secret_key, response.json());
            let sub = json.loads(rtn["sub"]);
            rtn.pop("sub");
            rtn["email"] = sub["email"];
            rtn["uid"] = sub["uid"];
            return rtn;
        }
        else throw new HTTPError(
            `Request failed with status code : ${response.status_code} \n this code contains a msg : ${response.text}`
        );
    }

    get_user(token: string): object {
        let url_ = 'https://api.trustauthx.com/api/user/me/auth/data';
        let headers = { 'accept': 'application/json' };
        let params = {
            'UserToken': token,
            'api_key': this.api_key,
            'signed_key': this.signed_key
        };
        let response = requests.get(url_, headers=headers, params=params);
        if (response.status_code == 200) {
            let rtn = this.jwt_decode(this.secret_key,response.json());
            let sub = json.loads(rtn["sub"]);
            rtn.pop("sub");
            rtn["email"] = sub["email"];
            rtn["uid"] = sub["uid"];
            return rtn;
        }
        else throw new HTTPError(
            `Request failed with status code : ${response.status_code} \n this code contains a msg : ${response.text}`
        );
    }

    get_access_token_from_refresh_token(refresh_token: string): object {
        let url_ = 'https://api.trustauthx.com/api/user/me/access/token/';
        let headers = { 'accept': 'application/json' };
        let params = {
            'RefreshToken': refresh_token,
            'api_key': this.api_key,
            'signed_key': this.signed_key
                 };
        let response = requests.get(url_, headers = headers, params = params);
        if (response.status_code == 200) return response.json();
        else throw new HTTPError(
            `Request failed with status code : ${response.status_code} \n this code contains a msg : ${response.text}`
        );
    }

    validate_access_token(access_token: string): boolean {
        let url_ = 'https://api.trustauthx.com/api/user/me/auth/validate/token';
        let headers = { 'accept': 'application/json' };
        let params = {
            'AccessToken': access_token,
            'api_key': this.api_key,
            'signed_key': this.signed_key
        };
        let response = requests.get(url_, headers = headers, params = params);
        return response.status_code == 200;
    }

    revoke_token(AccessToken?: string, RefreshToken?: string, revoke_all_tokens: boolean = false): object {
        let url_ = 'https://api.trustauthx.com/api/user/me/token/';
        let headers = { 'accept': 'application/json' };
        if (!AccessToken && !RefreshToken) throw new Error("must provide either AccessToken or RefreshToken");
        let tt = true if AccessToken else false;
        let t = AccessToken || RefreshToken;
        let params = {
            'Token': t,
            'api_key': this.api_key,
            'signed_key': this.signed_key,
            'AccessToken': tt,
            'SpecificTokenOnly': !revoke_all_tokens,
        };
        let response = requests.delete(url_, headers = headers, params = params);
        if (response.status_code == 200) return response.json();
        else throw new HTTPError(
            `Request failed with status code : ${response.status_code} \n this code contains a msg : ${response.text}`
        );
    }

    validate_token_set(access_token: string, refresh_token: string): TokenCheck {
        try {
            let d = new this.TokenCheck();
            let is_valid = this.validate_access_token(access_token);
            if (!is_valid) {
                if (refresh_token) {
                    let new_tokens = this.get_access_token_from_refresh_token(refresh_token);
                    d.state = false;
                    d.access = new_tokens['access_token'];
                    d.refresh = new_tokens['refresh_token'];
                }
                return d;
            } else {
                d.state = true;
                d.access = access_token;
                d.refresh = refresh_token;
                return d;
            }
        } catch (e) {
            throw new HTTPError('both tokens are invalid login again');
        }
    }
}
