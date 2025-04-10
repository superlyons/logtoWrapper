package logtoWrapper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gogf/gf/errors/gerror"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/logto-io/go/v2/client"
	"github.com/logto-io/go/v2/core"
)

func GetLogtoResMessageOrDetails(j *gjson.Json) string {
	if j.Get("details") == nil {
		return j.Get("message").String()
	} else {
		return j.Get("details").String()
	}
}

func VerifyToken(idToken, clientId, issuer string, jwks *jose.JSONWebKeySet) error {
	jws, err := core.ParseSignedJwt(idToken)
	if err != nil {
		return err
	}

	// Verify signature
	idTokenClaims := core.IdTokenClaims{}
	verifySignatureError := jws.Claims(jwks, &idTokenClaims)

	if verifySignatureError != nil {
		return verifySignatureError
	}

	// Verify claims
	if issuer != "" && idTokenClaims.Iss != issuer {
		return core.ErrTokenIssuerNotMatch
	}

	if clientId != "" && idTokenClaims.Aud != clientId {
		return core.ErrTokenAudienceNotMatch
	}

	now := time.Now().Unix()

	if idTokenClaims.Exp < now {
		return core.ErrTokenExpired
	}

	return nil
}
func VerifyAccessToken(ctx context.Context, token string, auds []string) error {
	cfg := g.Cfg()
	endPoint := cfg.MustGet(ctx, "logto.endpoint", "").String()
	appId := cfg.MustGet(ctx, "logto.appId", "").String()
	appSecret := cfg.MustGet(ctx, "logto.appSecret", "").String()
	if endPoint == "" || appId == "" || appSecret == "" {
		return errors.New("logto 必要配置缺失")
	}

	oidcConfig, oidcErr := GetOIDCConfig(ctx)
	if oidcErr != nil {
		return gerror.Wrap(oidcErr, "At VerifyToken")
	}

	// jwksResponse, fetchJwksErr := core.FetchJwks(httpClient, oidcConfig.JwksUri)
	jwksResponse, fetchJwksErr := GetJwks(ctx)
	if fetchJwksErr != nil {
		return gerror.Wrap(fetchJwksErr, "At FetchJwks")
	}

	jwks := jose.JSONWebKeySet{}
	for _, rawJsonWebKeyData := range jwksResponse.Keys {
		// Note: convert rawJsonWebKeyData to JSON string for we need to unmarshal it to JSONWebKey
		rawJsonWebKeyJsonString, parseToJsonWebKeyJsonErr := json.Marshal(rawJsonWebKeyData)
		if parseToJsonWebKeyJsonErr != nil {
			return gerror.Wrap(parseToJsonWebKeyJsonErr, "At json.Marshal(rawJsonWebKeyData)")
		}

		jwk := jose.JSONWebKey{}
		// Note: Use rawJsonWebKeyJsonString to construct the JsonWebKey
		parseToJsonWebKeyErr := jwk.UnmarshalJSON(rawJsonWebKeyJsonString)
		if parseToJsonWebKeyErr != nil {
			return gerror.Wrap(parseToJsonWebKeyErr, "At jwk.UnmarshalJSON(rawJsonWebKeyJsonString)")
		}

		jwks.Keys = append(jwks.Keys, jwk)
	}

	data, errData := GetTokenPayload(token)
	if errData != nil {
		return gerror.Wrap(errData, "At oidc issuer")
	}
	if oidcConfig.Issuer != data["iss"] {
		return gerror.Wrap(core.ErrTokenIssuerNotMatch, "At oidc issuer")
	}
	// var tokenAudience string
	if len(auds) > 0 {
		audsMap := WrapStrArrToMapBool(auds)
		if !audsMap[data["aud"].(string)] {
			return core.ErrTokenAudienceNotMatch
		}
	}
	verificationErr := VerifyToken(token, "", "", &jwks)

	if verificationErr != nil {
		return gerror.Wrap(verificationErr, "At VerifyIdToken")
	}
	return nil
}

func GetTokenPayload(token string) (map[string]interface{}, error) {
	tokenParts := strings.Split(token, ".")
	decoded, err1 := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err1 != nil {
		return map[string]interface{}{}, errors.New("DecodeString error = " + err1.Error())
	}
	var data map[string]interface{}
	err2 := json.Unmarshal(decoded, &data)
	if err2 != nil {
		return map[string]interface{}{}, errors.New("Unmarshal error = " + err2.Error())
	}
	return data, nil
}

func GetTokenAudience(token string) (string, error) {
	data, err := GetTokenPayload(token)
	if err != nil {
		return "", errors.New("GetTokenPayload = " + err.Error())
	}
	var aud string = data["aud"].(string)
	return aud, nil
}

func GetTokenScopes(token string) ([]string, error) {
	data, err := GetTokenPayload(token)
	if err != nil {
		return nil, errors.New("GetTokenPayload = " + err.Error())
	}
	if data["scope"] == nil {
		return nil, nil
	}
	var scopes string = data["scope"].(string)
	return strings.Split(scopes, " "), nil
}

func GetTokenSub(token string) (string, error) {
	data, err := GetTokenPayload(token)
	if err != nil {
		return "", errors.New("GetTokenPayload = " + err.Error())
	}
	var aud string = data["sub"].(string)
	return aud, nil
}

func WrapStrArrToMapBool(strarr []string) map[string]bool {
	var res map[string]bool = map[string]bool{}
	for _, v := range strarr {
		if v == "" {
			continue
		}
		res[v] = true
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

func GetOIDCConfig(ctx context.Context) (core.OidcConfigResponse, error) {
	redis := g.Redis()
	oidcConfigStr, _ := redis.Get(ctx, "oidc_config")
	var oidcConfig core.OidcConfigResponse
	if oidcConfigStr != nil && oidcConfigStr.String() != "" {
		json.Unmarshal([]byte(oidcConfigStr.String()), &oidcConfig)
		return oidcConfig, nil
	}

	httpClient := &http.Client{}
	cfg := g.Cfg()
	endPoint := cfg.MustGet(ctx, "logto.endpoint", "").String()
	if endPoint == "" {
		return core.OidcConfigResponse{}, errors.New("logto 必要配置缺失")
	}

	discoveryEndpoint, constructEndpointErr := url.JoinPath(endPoint, "/oidc/.well-known/openid-configuration")
	if constructEndpointErr != nil {
		return core.OidcConfigResponse{}, constructEndpointErr
	}
	oidcConfig, fetchOidcConfigErr := core.FetchOidcConfig(httpClient, discoveryEndpoint)
	if fetchOidcConfigErr != nil {
		return core.OidcConfigResponse{}, fetchOidcConfigErr
	}

	oidcJsonStr, odicJsonStrErr := json.Marshal(oidcConfig)
	if odicJsonStrErr != nil {
		return core.OidcConfigResponse{}, gerror.Wrap(odicJsonStrErr, "At json.Marshal(jwksResponse)")
	}
	redis.Set(ctx, "oidc_config", string(oidcJsonStr))
	log.Printf("OIDC Config From Request: %+v\n", string(oidcJsonStr))
	return oidcConfig, nil

}

func GetJwks(ctx context.Context) (core.JwksResponse, error) {
	redis := g.Redis()
	oidcJwks, _ := redis.Get(ctx, "oidc_jwks")
	var jwksResponse core.JwksResponse
	if oidcJwks != nil && oidcJwks.String() != "" {
		json.Unmarshal([]byte(oidcJwks.String()), &jwksResponse)
		return jwksResponse, nil
	}
	oidcConfig, oidcErr := GetOIDCConfig(ctx)
	if oidcErr != nil {
		return core.JwksResponse{}, gerror.Wrap(oidcErr, "At FetchJwks")
	}
	httpClient := &http.Client{}
	jwksResponse, err := core.FetchJwks(httpClient, oidcConfig.JwksUri)
	if err != nil {
		return core.JwksResponse{}, gerror.Wrap(err, "At FetchJwks")
	}
	jwksJsonStr, jwksJsonStrErr := json.Marshal(jwksResponse)
	if jwksJsonStrErr != nil {
		return core.JwksResponse{}, gerror.Wrap(jwksJsonStrErr, "At json.Marshal(jwksResponse)")
	}
	redis.Set(ctx, "oidc_jwks", string(jwksJsonStr))
	log.Printf("OIDC JWKS From Request: %+v\n", string(jwksJsonStr))
	return jwksResponse, nil
}

func buildAccessTokenKey(scopes []string, resource string, organizationId string) string {
	sort.Strings(scopes)
	scopesPart := strings.Join(scopes, " ")

	organizationPart := ""
	if organizationId != "" {
		organizationPart = "#" + organizationId
	}

	return scopesPart + "@" + resource + organizationPart
}

func verifyAndSaveTokenResponse(
	ctx context.Context,
	idToken string,
	refreshToken string,
	accessTokenKey string,
	accessToken client.AccessToken,
	oidcConfig *core.OidcConfigResponse,
	appId string,
	logtoClient *client.LogtoClient,
) error {
	if idToken != "" {
		jwksResponse, fetchJwksErr := GetJwks(ctx)
		if fetchJwksErr != nil {
			return fetchJwksErr
		}

		jwks := jose.JSONWebKeySet{}
		for _, rawJsonWebKeyData := range jwksResponse.Keys {
			// Note: convert rawJsonWebKeyData to JSON string for we need to unmarshal it to JSONWebKey
			rawJsonWebKeyJsonString, parseToJsonWebKeyJsonErr := json.Marshal(rawJsonWebKeyData)
			if parseToJsonWebKeyJsonErr != nil {
				return parseToJsonWebKeyJsonErr
			}

			jwk := jose.JSONWebKey{}
			// Note: Use rawJsonWebKeyJsonString to construct the JsonWebKey
			parseToJsonWebKeyErr := jwk.UnmarshalJSON(rawJsonWebKeyJsonString)
			if parseToJsonWebKeyErr != nil {
				return parseToJsonWebKeyErr
			}

			jwks.Keys = append(jwks.Keys, jwk)
		}

		verificationErr := core.VerifyIdToken(idToken, appId, oidcConfig.Issuer, &jwks)
		if verificationErr != nil {
			return verificationErr
		}

		logtoClient.SetIdToken(idToken)
	}

	logtoClient.SetRefreshToken(refreshToken)

	logtoClient.SaveAccessToken(accessTokenKey, accessToken)
	return nil
}
