# The push simulator (FR-MFA-03).
#
# Its own image rather than a second entrypoint on the broker's, because the
# broker's runtime image should not carry a service that can approve second
# factors. Shipping the simulator inside the thing it simulates for is how a
# development shortcut reaches production.
FROM python:3.12-slim

WORKDIR /app

# Pinned like everything else. A simulator with a floating dependency is still a
# build that can break on a Tuesday.
RUN pip install --no-cache-dir fastapi==0.115.6 "uvicorn[standard]==0.34.0"

COPY app.py /app/app.py

# Non-root, for the same reason every other container here is.
RUN useradd --system --uid 10001 pushsim
USER 10001

EXPOSE 8100
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8100"]
