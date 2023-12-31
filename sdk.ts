import { decode, encode, JWTError } from 'jsonwebtoken';
import { ALGORITHMS } from 'jsonwebtoken';

class AuthLiteClient {
  private secretKey: string;
  private apiKey: string;
  private orgId?: string;
  private signedKey: string;

  constructor(apiKey: string, secretKey: string, orgId?: string) {
    this.secretKey = secretKey;
    this.apiKey = apiKey;
    this.orgId = orgId;
    this.signedKey = this.jwtEncode(secretKey, { api_key: apiKey });
  }

  private jwtEncode(key: string, data: object): string {
    return encode(data, key, { algorithm: ALGORITHMS.HS256 });
  }

  private jwtDecode(key: string, data: string): object {
    return decode(data, key, { algorithms: [ALGORITHMS.HS256] }) as object;
  }

  generateUrl(): string {
    if (this.orgId) {
      return `https://app.trustauthx.com/widget/login/?org_id=${this.orgId}`;
    } else {
      throw new Error('Must provide org_id');
    }
  }

  generateEditUserUrl(accessToken: string, url: string): string {
    const headers = { accept: 'application/json' };
    const params = new URLSearchParams({
      AccessToken: accessToken,
      api_key: this.apiKey,
      signed_key: this.signedKey,
      url: url,
    });

    return fetch('https://api.trustauthx.com/api/user/me/settings/?' + params.toString(), {
      method: 'GET',
      headers: headers,
    }).then((response) => {
      return response.url;
    });
  }

  async reAuth(code: string): Promise<object> {
    const url = 'https://api.trustauthx.com/api/user/me/widget/re-auth/token';
    const params = new URLSearchParams({
      code: code,
      api_key: this.apiKey,
      signed_key: this.signedKey,
    });
    const headers = { accept: 'application/json' };

    try {
      const response = await fetch(url + '?' + params.toString(), {
        method: 'GET',
        headers: headers,
      });

      if (response.status === 200) {
        const data = await response.json();
        const rtn = this.jwtDecode(this.secretKey, JSON.stringify(data));
        const sub = JSON.parse(rtn['sub']);
        delete rtn['sub'];
        rtn['email'] = sub['email'];
        rtn['uid'] = sub['uid'];
        return rtn;
      } else {
        throw new Error(`Request failed with status code: ${response.status}\n${await response.text()}`);
      }
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  async getUser(token: string): Promise<object> {
    const url = 'https://api.trustauthx.com/api/user/me/auth/data';
    const params = new URLSearchParams({
      UserToken: token,
      api_key: this.apiKey,
      signed_key: this.signedKey,
    });
    const headers = { accept: 'application/json' };

    try {
      const response = await fetch(url + '?' + params.toString(), {
        method: 'GET',
        headers: headers,
      });

      if (response.status === 200) {
        const data = await response.json();
        const rtn = this.jwtDecode(this.secretKey, JSON.stringify(data));
        const sub = JSON.parse(rtn['sub']);
        delete rtn['sub'];
        rtn['email'] = sub['email'];
        rtn['uid'] = sub['uid'];
        return rtn;
      } else {
        throw new Error(`Request failed with status code: ${response.status}\n${await response.text()}`);
      }
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  async getAccessTokenFromRefreshToken(refreshToken: string): Promise<object> {
    const url = 'https://api.trustauthx.com/api/user/me/access/token/';
    const params = new URLSearchParams({
      RefreshToken: refreshToken,
      api_key: this.apiKey,
      signed_key: this.signedKey,
    });
    const headers = { accept: 'application/json' };

    try {
      const response = await fetch(url + '?' + params.toString(), {
        method: 'GET',
        headers: headers,
      });

      if (response.status === 200) {
        return await response.json();
      } else {
        throw new Error(`Request failed with status code: ${response.status}\n${await response.text()}`);
      }
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  async validateAccessToken(access_token: string): Promise<boolean> {
    const url = 'https://api.trustauthx.com/api/user/me/auth/validate/token';
    const params = new URLSearchParams({
      AccessToken: access_token,
      api_key: this.apiKey,
      signed_key: this.signedKey,
    });
    const headers = { accept: 'application/json' };

    try {
      const response = await fetch(url + '?' + params.toString(), {
        method: 'GET',
        headers: headers,
      });

      return response.status === 200;
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  async revokeToken(AccessToken: string | null = null, RefreshToken: string | null = null, revokeAllTokens: boolean = false): Promise<boolean> {
    const url = 'https://api.trustauthx.com/api/user/me/token/';
    const headers = { accept: 'application/json' };

    if (!AccessToken && !RefreshToken) {
      throw new Error('Must provide either AccessToken or RefreshToken');
    }

    const tt = !!AccessToken;
    const t = AccessToken || RefreshToken;
    const params = new URLSearchParams({
      Token: t,
      api_key: this.apiKey,
      signed_key: this.signedKey,
      AccessToken: tt.toString(),
      SpecificTokenOnly: (!revokeAllTokens).toString(),
    });

    try {
      const response = await fetch(url + '?' + params.toString(), {
        method: 'DELETE',
        headers: headers,
      });

      return response.status === 200;
    } catch (error) {
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  async validateTokenSet(access_token: string, refresh_token: string): Promise<TokenCheck> {
    try {
      const d: TokenCheck = {
        access: '',
        refresh: '',
        state: false,
      };
      const is_valid = await this.validateAccessToken(access_token);
      if (!is_valid) {
        if (refresh_token) {
          const new_tokens = await this.getAccessTokenFromRefreshToken(refresh_token);
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
    } catch (error) {
      throw new Error('Both tokens are invalid, please log in again',error);
    }
  }
}

class TokenCheck {
  access: string;
  refresh: string;
  state: boolean;
}
