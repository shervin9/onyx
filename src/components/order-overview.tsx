"use client"
import {useAppContext} from "@/providers/context-provider";
import OrderItem from "@/components/order-item";

export default function OrderOverview() {
    const {state, dispatch} = useAppContext()

    const items = Array.from(state.cart.values())
        .map((cartItem) => <OrderItem key={cartItem.product.id} id={cartItem.product.id}/>)

    return (
        <section className="order-overview">
            <div className="order-block">
                <div className="order-header-wrap">
                    <h2 className="order-header">سفارش شما</h2>
                    <span className="order-edit"
                          onClick={() => dispatch({type: "storefront"})}>ویرایش سفارش</span>
                </div>
                <div className="order-items">
                    {items}
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="افزودن توضیحات"
                        onChange={(e) =>
                            dispatch({type: "comment", comment: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                    مثلا قبل ارسال تماس گرفته شود....
                </div>
            </div>
            <div className="order-text-field-wrap">
                    <textarea
                        className="order-text-field order-block"
                        rows={1}
                        placeholder="آدرس شما"
                        onChange={(e) =>
                            dispatch({type: "address", address: e.currentTarget.value})
                        }
                    ></textarea>
                <div className="order-text-field-hint">
                     آدرس جهت ارسال کالا
                </div>
            </div>
        </section>
    )
}
