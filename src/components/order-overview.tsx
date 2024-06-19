"use client"
import {useAppContext} from "@/providers/context-provider";
import OrderItem from "@/components/order-item";
import { useState } from 'react'

export default function OrderOverview() {
    const {state, dispatch} = useAppContext()
    const [isPaymentOnline, setIsPaymentOnline] = useState("onlinePay")


    const items = Array.from(state.cart.values())
        .map((cartItem) => <OrderItem key={cartItem.product.id} id={cartItem.product.id}/>)

    return (
        <section className="order-overview" dir="rtl">
            <div className="order-block">
                <div className="order-header-wrap">
                    <h2 className="order-header">سفارش شما</h2>
                    <span className="order-edit"
                          onClick={() => dispatch({type: "storefront"})}>ویرایش</span>
                </div>
                <div className="order-items">
                    {items}
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="نام …"
                        onChange={(e) =>
                            dispatch({type: "name", name: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="نام خانوادگی …"
                        onChange={(e) =>
                            dispatch({type: "lName", lName: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="شماره تماس …"
                        onChange={(e) =>
                            dispatch({type: "phone", phone: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    مشخصات مشتری
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="استان…"
                        onChange={(e) =>
                            dispatch({type: "province", province: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="شهر …"
                        onChange={(e) =>
                            dispatch({type: "city", city: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="آدرس شما …"
                        onChange={(e) =>
                            dispatch({type: "address", address: e.currentTarget.value})
                        }
                    ></textarea>
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="کد پستی …"
                        onChange={(e) =>
                            dispatch({type: "postcode", postcode: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    آدرس کامل گیرنده
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="توضیحات …"
                        onChange={(e) =>
                            dispatch({type: "comment", comment: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    توضیحات، جزییات و یا درخواست های شما...
                </div>
            </div>
            <div className="order-text-field-wrap">
            <tbody>
          <tr>
            <td>
              <input
                type="radio"
                name="onlinePay"
                value={"onlinePay"}
                checked={isPaymentOnline === "onlinePay"}
                disabled={false}  
                onChange={(e) => setIsPaymentOnline(e.target.value)}
              />
              پرداخت اینترنتی
            </td>
            <td>
              <input
                type="radio"
                name="offlinePay"
                value={"offlinePay"}
                checked={isPaymentOnline === "offlinePay"}
                disabled={false}  
                onChange={(e) => setIsPaymentOnline(e.target.value)}
              />
              پرداخت در محل
            </td>
          </tr>
        </tbody>
                <div className="order-text-field-hint">
                    روش پرداخت
                </div>
            </div>
        </section>
    )
}
