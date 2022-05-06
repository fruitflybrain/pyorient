"""PyOrient exceptions."""


class PyOrientException(Exception):
    def __init__(self, message, errors):

        _errorClass = message.split(".")[-1]

        exception_mapper = {
            "OAccessToSBtreeCollectionManagerIsProhibitedException": PyOrientSecurityAccessException,
            "OBackupInProgressException": PyOrientBackupInProgressException,
            "OCommandExecutorNotFoundException": PyOrientCommandException,
            "OCommandExecutionException": PyOrientCommandException,
            "OCommandScriptException": PyOrientCommandException,
            "OCommandSQLParsingException": PyOrientSQLParsingException,
            "OConfigurationException": PyOrientConfigurationException,
            "ODatabaseException": PyOrientDatabaseException,
            "ODurableComponentException": PyOrientDurableComponentException,
            "OFetchException": PyOrientFetchException,
            "OIndexEngineException": PyOrientIndexException,
            "OIndexException": PyOrientIndexException,
            "OLiveQueryInterruptedException": PyOrientLiveQueryInterruptedException,
            "OModificationOperationProhibitedException": PyOrientModificationOperationProhibitedException,
            "ONeedRetryException": PyOrientNeedRetryException,
            "OOfflineClusterException": PyOrientOfflineClusterException,
            "ORecordDuplicatedException": PyOrientORecordDuplicatedException,
            "ORecordNotFoundException": PyOrientRecordNotFoundException,
            "ORetryQueryException": PyOrientNeedRetryException,
            "OSchemaException": PyOrientSchemaException,
            "OSecurityAccessException": PyOrientSecurityAccessException,
            "OSecurityException": PyOrientSecurityException,
            "OSequenceException": PyOrientSequenceException,
            "OSerializationException": PyOrientSerializationException,
            "OStorageException": PyOrientStorageException,
            "OTooBigIndexKeyException": PyOrientTooBigIndexKeyException,
            "OTokenSecurityException": PyOrientSecurityException,
            "OTransactionException": PyOrientTransactionException,
            "OValidationException": PyOrientValidationException,
            "OWriteCacheException": PyOrientWriteCacheException,
        }

        # Override the exception Type with OrientDB exception map
        if _errorClass in exception_mapper.keys():
            self.__class__ = exception_mapper[_errorClass]

        Exception.__init__(self, message)
        # errors is an array of tuple made this way:
        # ( java_exception_class,  message)
        self.errors = errors

    def __str__(self):
        if self.errors:
            return "%s - %s" % (Exception.__str__(self), self.errors[0])

        else:
            return Exception.__str__(self)


class PyOrientWriteCacheException(PyOrientException):
    pass


class PyOrientValidationException(PyOrientException):
    pass


class PyOrientTransactionException(PyOrientException):
    pass


class PyOrientTooBigIndexKeyException(PyOrientException):
    pass


class PyOrientStorageException(PyOrientException):
    pass


class PyOrientSerializationException(PyOrientException):
    pass


class PyOrientSequenceException(PyOrientException):
    pass


class PyOrientSecurityException(PyOrientException):
    pass


class PyOrientRecordNotFoundException(PyOrientException):
    pass


class PyOrientNeedRetryException(PyOrientException):
    pass


class PyOrientOfflineClusterException(PyOrientException):
    pass


class PyOrientModificationOperationProhibitedException(PyOrientException):
    pass


class PyOrientLiveQueryInterruptedException(PyOrientException):
    pass


class PyOrientFetchException(PyOrientException):
    pass


class PyOrientDurableComponentException(PyOrientException):
    pass


class PyOrientBackupInProgressException(PyOrientException):
    pass


class PyOrientConfigurationException(PyOrientException):
    pass


class PyOrientConnectionException(PyOrientException):
    pass


class PyOrientConnectionPoolException(PyOrientException):
    pass


class PyOrientSecurityAccessException(PyOrientException):
    pass


class PyOrientDatabaseException(PyOrientException):
    pass


class PyOrientSQLParsingException(PyOrientException):
    pass


class PyOrientCommandException(PyOrientException):
    pass


class PyOrientSchemaException(PyOrientException):
    pass


class PyOrientIndexException(PyOrientException):
    pass


class PyOrientORecordDuplicatedException(PyOrientException):
    pass


class PyOrientBadMethodCallException(PyOrientException):
    pass


class PyOrientWrongProtocolVersionException(PyOrientException):
    pass


class PyOrientSerializationException(PyOrientException):
    pass


class PyOrientNullRecordException(PyOrientException):
    pass
