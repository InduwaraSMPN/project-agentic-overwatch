"""The load script every profile in infra/locust/profiles.yaml names.

A NOTE ON THE WRAP WIDTH
    This file wraps at 96 columns rather than the repository's usual 100. A verbatim copy of
    it is embedded, indented by four spaces, in the ConfigMap inside
    infra/locust/deployment.yaml -- that is how the script reaches the cluster, and a test
    holds the two byte for byte identical. Four columns of headroom here is what keeps the
    embedded copy inside the same 100-column wrap as everything else in the repository.

WHAT THIS DRIVES
    Online Boutique's frontend, over the same four paths a browsing customer walks: the home
    page, a product page, adding that product to the cart, and viewing the cart. Those are
    the paths that fan out to the most backend services -- the home page alone calls
    productcatalogservice, currencyservice and adservice, and the cart pages add cartservice
    and its Redis store -- so a load profile built from them exercises the service graph
    rather than one edge of it. A synthetic endpoint that touched only the frontend would
    report interference figures no incident scenario could ever reproduce.

WHY THERE IS NO CHECKOUT TASK
    Checkout is the one Boutique path that mutates state which outlives the request. Each
    order placed is an order emailed, a shipping quote tracked and a cart emptied, and those
    side effects accumulate across every run in a campaign, so the hundredth run drives an
    application in a different state from the first. That is precisely the run-to-run
    variance this component exists to remove, and it would land inside the RQ4 interference
    delta as noise varying with campaign position rather than with the framework. The
    checkout form also takes a payment-card field, and a load script that fills one -- with
    any value, synthetic or not -- is a load script nobody can read at a glance and be sure
    about. Adding to cart is already a write path, so the profile is not read-only; it is
    bounded, which is the property that matters.

DETERMINISM
    .agents/rules/20-parity-and-determinism.md forbids unseeded randomness on any path a run
    depends on, and this file is on one. Two consequences are visible below.

    The think time is constant, not drawn from a range. Locust's `between` samples an
    unseeded uniform distribution, so two runs of the same profile would issue different
    numbers of requests over the same window and the interference delta would carry that
    difference as though it were an effect.

    The product a task visits comes from a fixed cycle over the catalogue, not from a random
    choice. Each simulated user walks the same nine products in the same order, so the mix of
    backend calls a run produces is a function of how many tasks ran and nothing else. The
    cycle is per user instance rather than module level, because a shared iterator would make
    the sequence depend on the interleaving of concurrent greenlets, which is exactly the
    wall-clock dependence the rule rules out.

    What remains random is Locust's own weighted choice of which task to run next, which the
    M1 plan admits explicitly: the alternative is a fixed task order, and a fixed order is not
    a load profile but a script, with the queueing behaviour of a batch job rather than of
    traffic.

HOST
    Deliberately not set here. A `host` attribute on the user class would be a second home for
    the value infra/locust/profiles.yaml already carries per profile, and the two would drift
    the first time the application moved namespace. The host arrives at swarm time, from the
    profile the run names -- see infra/locust/deployment.yaml for the mechanism.

WHAT BREAKS IF THIS FILE CHANGES
    The task weights and the think time together define what `users` means in a profile:
    ten users at one think time is not the same load as ten users at another. Changing either
    silently redefines every profile in the registry, and so breaks comparability with every
    run already recorded -- without changing `load_profile_id`, which is the field a bundle
    carries to say what load it saw. A change here is a new profile, not an edit to this one.
"""

import itertools

from locust import HttpUser, constant, task

# The nine product identifiers Online Boutique's catalogue ships at the pinned release. They
# are stable data rather than configuration: they come from productcatalogservice's own
# products.json and change only when the application changes, which is a version bump and a
# re-pin. Listed here rather than discovered at runtime, because discovering them would make
# the load script's behaviour depend on a response it also measures.
PRODUCT_IDS = (
    "OLJCESPC7Z",
    "66VCHSJNUP",
    "1YMWWN1N4O",
    "L9ECAV7KIM",
    "2ZYFJ3GM2N",
    "0PUK6V6EV0",
    "LS4PSXUNUM",
    "9SIQT8TOJO",
    "6E92ZMYYFZ",
)


class BoutiqueUser(HttpUser):
    """One simulated shopper browsing Online Boutique's frontend."""

    # A fixed one-second pause between tasks. See DETERMINISM in the module docstring: this
    # is the value that turns `users` in a profile into a defined request rate instead of an
    # approximate one, so it is as load-bearing as the user count itself.
    wait_time = constant(1)

    def on_start(self) -> None:
        """Give this user its own position in the catalogue cycle."""
        self._products = itertools.cycle(PRODUCT_IDS)

    def _next_product(self) -> str:
        return next(self._products)

    @task(4)
    def view_home(self) -> None:
        """The landing page: productcatalogservice, currencyservice, adservice."""
        self.client.get("/", name="/")

    @task(4)
    def view_product(self) -> None:
        """A product detail page, which also pulls recommendations and an ad.

        Reported under a single stats name rather than one per identifier. Nine separate
        rows would split the sample nine ways and make the p95 of each far noisier than the
        p95 of the page, which is the figure evaluation-protocol section 3's interference
        measure actually reads.
        """
        self.client.get(f"/product/{self._next_product()}", name="/product/[id]")

    @task(2)
    def add_to_cart(self) -> None:
        """Add one unit of the next product to this user's cart.

        The frontend answers with a redirect to the cart page and the client follows it, so
        the latency recorded for this row is the user-visible cost of the whole
        add-then-see-cart round trip. That is deliberate and it is consistent across every
        run, so it cancels in the framework-on minus baseline delta rather than biasing it.
        """
        self.client.post(
            "/cart",
            data={"product_id": self._next_product(), "quantity": 1},
            name="/cart [add]",
        )

    @task(1)
    def view_cart(self) -> None:
        """The cart page: cartservice, its Redis store, and a shipping quote."""
        self.client.get("/cart", name="/cart")
