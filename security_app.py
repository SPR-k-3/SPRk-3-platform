import streamlit as st
from sprk3_security import SPRk3Security

st.title("SPR{K}3 Security Monitor")

security = SPRk3Security()

user_input = st.text_area("Test input:", "Type here", height=150)

col1, col2 = st.columns(2)

with col1:
    if st.button("Scan"):
        is_safe, triggers = security.check_input(user_input)
        if is_safe:
            st.success("Safe!")
        else:
            st.error(f"{len(triggers)} threats!")
            for t in triggers:
                st.warning(f"{t.trigger_type.value}")

with col2:
    if st.button("Clean"):
        clean = security.sanitize_input(user_input)
        st.code(clean)

if st.button("Test Zero-Width"):
    test = "Test" + chr(0x200b)
    _, triggers = security.check_input(test)
    st.success(f"Detected {len(triggers)} threats!")
