from rest_framework import throttling


class BasicPasswordAuthThrottle(throttling.AnonRateThrottle):
    rate = "10/minute"


class BasicTokenRefreshThrottle(throttling.UserRateThrottle):
    rate = "1/minute"
