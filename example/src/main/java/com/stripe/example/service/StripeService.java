
package com.stripe.example.service;

import java.util.Map;

import okhttp3.ResponseBody;
import retrofit2.http.FieldMap;
import retrofit2.http.FormUrlEncoded;
import retrofit2.http.POST;
import rx.Observable;

/**
 * A Retrofit service used to communicate with a server.
 */
public interface StripeService {

    @FormUrlEncoded
    @POST("ephemeral_keys")
    Observable<ResponseBody> createEphemeralKey(@FieldMap Map<String, String> apiVersionMap);

    @FormUrlEncoded
    @POST("create_charge")
    Observable<ResponseBody> charge(@FieldMap Map<String, String> charge);

    @FormUrlEncoded
    @POST("charge")
    Observable<ResponseBody> customerCharge(@FieldMap Map<String, String> charge);

    @FormUrlEncoded
    @POST("subscribe")
    Observable<ResponseBody> customerSubscribe(@FieldMap Map<String, String> subscribe);
}
