# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022 Valory AG
#   Copyright 2018-2021 Fetch.AI Limited
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""This scripts contains code from agent-vs-aea.md file."""

import os
import time
from threading import Thread

from aea_ledger_fetchai import FetchAICrypto

from aea.aea_builder import AEABuilder
from aea.configurations.base import SkillConfig
from aea.crypto.helpers import PRIVATE_KEY_PATH_SCHEMA, create_private_key
from aea.helpers.file_io import write_with_lock
from aea.skills.base import Skill


ROOT_DIR = "./"
INPUT_FILE = "input_file"
OUTPUT_FILE = "output_file"
FETCHAI_PRIVATE_KEY_FILE = PRIVATE_KEY_PATH_SCHEMA.format(FetchAICrypto.identifier)


def run():
    """Run demo."""

    # Create a private key
    create_private_key(FetchAICrypto.identifier, FETCHAI_PRIVATE_KEY_FILE)

    # Ensure the input and output files do not exist initially
    if os.path.isfile(INPUT_FILE):
        os.remove(INPUT_FILE)
    if os.path.isfile(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    # Instantiate the builder and build the AEA
    # By default, the default protocol, error skill and stub connection are added
    builder = AEABuilder()

    builder.set_name("my_aea")

    builder.add_private_key(FetchAICrypto.identifier, FETCHAI_PRIVATE_KEY_FILE)

    # Add the default protocol (assuming it is present in the local directory 'packages')
    builder.add_protocol("./packages/fetchai/protocols/default")

    # Add the stub connection (assuming it is present in the local directory 'packages')
    builder.add_connection("./packages/fetchai/connections/stub")

    # Add the echo skill (assuming it is present in the local directory 'packages')
    builder.add_skill("./packages/fetchai/skills/echo")

    # create skill and handler manually
    from aea.protocols.base import Message
    from aea.skills.base import Handler

    from packages.fetchai.protocols.default.message import DefaultMessage

    class DummyHandler(Handler):
        """Dummy handler to handle messages."""

        SUPPORTED_PROTOCOL = DefaultMessage.protocol_id

        def setup(self) -> None:
            """Noop setup."""

        def teardown(self) -> None:
            """Noop teardown."""

        def handle(self, message: Message) -> None:
            """Handle incoming message."""
            self.context.logger.info("You got a message: {}".format(str(message)))

    config = SkillConfig(name="test_skill", author="fetchai")
    skill = Skill(configuration=config)
    dummy_handler = DummyHandler(
        name="dummy_handler", skill_context=skill.skill_context
    )
    skill.handlers.update({dummy_handler.name: dummy_handler})
    builder.add_component_instance(skill)

    # Create our AEA
    my_aea = builder.build()

    # Set the AEA running in a different thread
    try:
        t = Thread(target=my_aea.start)
        t.start()

        # Wait for everything to start up
        time.sleep(4)

        # Create a message inside an envelope and get the stub connection to pass it on to the echo skill
        message_text = b"my_aea,other_agent,fetchai/default:1.0.0,\x12\x10\x08\x01\x12\x011*\t*\x07\n\x05hello,"
        with open(INPUT_FILE, "wb") as f:
            write_with_lock(f, message_text)
            print(b"input message: " + message_text)

        # Wait for the envelope to get processed
        time.sleep(4)

        # Read the output envelope generated by the echo skill
        with open(OUTPUT_FILE, "rb") as f:
            print(b"output message: " + f.readline())
    finally:
        # Shut down the AEA
        my_aea.stop()
        t.join()
        t = None


if __name__ == "__main__":
    run()
