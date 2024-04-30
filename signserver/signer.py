from abc import ABCMeta, abstractmethod

class Signer(metaclass=ABCMeta):
    """
    Abstract base class for signers.

    This class defines the interface for signers, which are responsible for signing a digest using a specific algorithm.

    Subclasses must implement the `sign` method to perform the actual signing operation and the `close` method to clean up any resources used by the signer.
    """

    @abstractmethod
    def sign(self, digest, digest_algorithm):
        """
        Signs the given digest using the specified digest algorithm.

        Parameters:
        - digest: The digest to be signed.
        - digest_algorithm: The algorithm used to compute the digest.

        Returns:
        None
        """

    @abstractmethod
    def close(self):
        """
        Release resources.
        """
