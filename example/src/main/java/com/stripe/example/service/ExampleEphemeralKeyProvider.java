package com.stripe.example.service;

import android.support.annotation.NonNull;
import android.support.annotation.Size;

import com.stripe.android.EphemeralKeyProvider;
import com.stripe.android.EphemeralKeyUpdateListener;
import com.stripe.android.PaymentSessionData;
import com.stripe.android.model.Customer;
import com.stripe.example.module.RetrofitFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import okhttp3.ResponseBody;
import retrofit2.Retrofit;
import rx.android.schedulers.AndroidSchedulers;
import rx.functions.Action1;
import rx.schedulers.Schedulers;
import rx.subscriptions.CompositeSubscription;

/**
 * An implementation of {@link EphemeralKeyProvider} that can be used to generate
 * ephemeral keys on the backend.
 */
public class ExampleEphemeralKeyProvider implements EphemeralKeyProvider {

    private @NonNull CompositeSubscription mCompositeSubscription;
    private @NonNull StripeService mStripeService;
    private @NonNull ProgressListener mProgressListener;

    public ExampleEphemeralKeyProvider(@NonNull ProgressListener progressListener) {
        Retrofit retrofit = RetrofitFactory.getInstance();
        mStripeService = retrofit.create(StripeService.class);
        mCompositeSubscription = new CompositeSubscription();
        mProgressListener = progressListener;
    }


    public StripeService stripeService() {
        return mStripeService;
    }

    public void customerSubscribe(@NonNull final PaymentSessionData data, @NonNull final Customer customer) {
        final String paymentToken = data.getSelectedPaymentMethodId();
        final Map<String, String> map = new HashMap<>();
        System.out.println("yo: " + paymentToken);
        map.put("customer_id", customer.getId());
        //map.put("shipping", data.getShippingMethod().getIdentifier());
        mCompositeSubscription.add(
                mStripeService.customerSubscribe(map)
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribe(new Action1<ResponseBody>() {
                            @Override
                            public void call(ResponseBody response) {
                                try {
                                    String rawKey = response.string();
                                    mProgressListener.onStringResponse(rawKey);
                                } catch (IOException iox) {
                                }
                            }
                        }, new Action1<Throwable>() {
                            @Override
                            public void call(Throwable throwable) {
                                mProgressListener.onStringResponse(throwable.getMessage());
                            }
                        }));
    }

    public void customerCharge(@NonNull final PaymentSessionData data, @NonNull final Customer customer) {
        final String paymentToken = data.getSelectedPaymentMethodId();
        final Map<String, String> map = new HashMap<>();
        System.out.println("yo: " + paymentToken);
        map.put("amount", "123");
        map.put("source", paymentToken);
        map.put("customer_id", customer.getId());
        //map.put("shipping", data.getShippingMethod().getIdentifier());
        mCompositeSubscription.add(
                mStripeService.customerCharge(map)
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribe(new Action1<ResponseBody>() {
                            @Override
                            public void call(ResponseBody response) {
                                try {
                                    String rawKey = response.string();
                                    mProgressListener.onStringResponse(rawKey);
                                } catch (IOException iox) {
                                }
                            }
                        }, new Action1<Throwable>() {
                            @Override
                            public void call(Throwable throwable) {
                                mProgressListener.onStringResponse(throwable.getMessage());
                            }
                        }));
    }

    public void charge(@NonNull final String paymentToken) {
        final Map<String, String> map = new HashMap<>();
        System.out.println("yo: " + paymentToken);
        map.put("amount", "123");
        map.put("source", paymentToken);
        mCompositeSubscription.add(
                mStripeService.charge(map)
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribe(new Action1<ResponseBody>() {
                            @Override
                            public void call(ResponseBody response) {
                                try {
                                    String rawKey = response.string();
                                    mProgressListener.onStringResponse(rawKey);
                                } catch (IOException iox) {
                                }
                            }
                        }, new Action1<Throwable>() {
                            @Override
                            public void call(Throwable throwable) {
                                mProgressListener.onStringResponse(throwable.getMessage());
                            }
                        }));
    }

    @Override
    public void createEphemeralKey(@NonNull @Size(min = 4) String apiVersion,
                                   @NonNull final EphemeralKeyUpdateListener keyUpdateListener) {
        Map<String, String> apiParamMap = new HashMap<>();
        apiParamMap.put("api_version", apiVersion);

        mCompositeSubscription.add(
                mStripeService.createEphemeralKey(apiParamMap)
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribe(new Action1<ResponseBody>() {
                            @Override
                            public void call(ResponseBody response) {
                                try {
                                    String rawKey = response.string();
                                    keyUpdateListener.onKeyUpdate(rawKey);
                                    mProgressListener.onStringResponse(rawKey);
                                } catch (IOException iox) {

                                }
                            }
                        }, new Action1<Throwable>() {
                            @Override
                            public void call(Throwable throwable) {
                                mProgressListener.onStringResponse(throwable.getMessage());
                            }
                        }));
    }

    public interface ProgressListener {
        void onStringResponse(String string);
    }
}
