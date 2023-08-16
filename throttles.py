from rest_framework import throttling


class OnePerMinuteThrottle(throttling.UserRateThrottle):
    rate = "1/minute"


class BasicPasswordAuthThrottle(throttling.AnonRateThrottle):
    rate = "10/minute"


class BasicTokenRefreshThrottle(OnePerMinuteThrottle):
    rate = "1/minute"
