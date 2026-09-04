
from app.analytics.analytics_engine import analytics_engine

try:
    print("Testing analytics engine...")
    dashboard_data = analytics_engine.dashboard()
    print("Dashboard data:", dashboard_data)
    print("SUCCESS: Analytics engine works!")
except Exception as e:
    print(f"ERROR in analytics engine: {e}")
    import traceback
    traceback.print_exc()