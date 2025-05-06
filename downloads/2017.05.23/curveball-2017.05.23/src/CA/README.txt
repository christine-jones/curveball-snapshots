This is home of the BBN Curveball Development Certificate Authority (CA).

Included in the CERTS directory are a collection of host certs intended
for use in testbeds.

This is NOT a real certificate authority and is useful only to create
certificates for a testbed.  The certificates in the CERTS directory
should not be trusted outside a testbed.

The current concept is that we will use the script make-node-cert to create
certs for each node that needs one, and we'll do this in batches that are
coordinated to prevent the creation of redundant or contradictory certs.

It can get awkward to use the make-node-cert script on more than one branch,
because the CA needs to keep some state across invocations, and there's no way
to merge this state from one branch to another.  Therefore, the recommended
practice is to use this script only on master and only at the tip of master, to
avoid merge conflicts.

Here's an example session:

$ git checkout master
$ git remote update -p
$ git merge --ff-only origin/master

    If the merge fails, then reconcile any differences between your local
    version of master and origin/master.  Don't continue until you have every
    change on origin/master merged into your working master.

$ cd src/CA
$ ./make-node-cert name1 .. nameN

    name1 ... nameN are fully qualified domain names for each host.

    Names should be all lower-case (and other valid non-alphabetic
    characters).  I don't think these tools properly support anything
    other than the ASCII character set right now.

    Note that make-node-cert will not create a key or cert for a node that
    already has a key or cert.  If you need to "overwrite" an existing cert,
    you need to remove the current key and pem files for that host and re-run
    the script.

$ git add CERTS/name1.key CERTS/name1.pem ... CERTS/nameN.key CERTS/nameK.pem
$ git commit CERTS/*

    Read the commit message carefully and check that no extra files
    snuck in.

$ git push

    The push may fail if someone else pushed something to master after you did
    your remote update and merge.  If so, then do another remote update, and
    look at the log on origin/master.  If the other person was also making
    changes to CA, then the safest thing to do is to abandon your changes and
    start this process over again.  Otherwise, update, rebase and push again.

    NOTE that merge conflicts on files in CA/CA CANNOT be resolved.  A conflict
    means that the CA data was updated concurrently in two places, and the CA
    protocol DOES NOT tolerate this.  CAs and SCMs don't play well with each
    other.
